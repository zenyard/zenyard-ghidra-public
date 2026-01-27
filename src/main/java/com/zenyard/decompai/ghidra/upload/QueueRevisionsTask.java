package com.zenyard.decompai.ghidra.upload;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.zenyard.decompai.ghidra.api.generated.model.GlobalVariable;
import com.zenyard.decompai.ghidra.api.generated.model.ModelObject;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.events.EventConsumer;
import com.zenyard.decompai.ghidra.events.EventDispatcher;
import com.zenyard.decompai.ghidra.events.EventProducer;
import com.zenyard.decompai.ghidra.inferences.PendingInferenceManager;
import com.zenyard.decompai.ghidra.illum.FunctionOverviewAnnotator;
import com.zenyard.decompai.ghidra.illum.InferenceApplier;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;
import com.zenyard.decompai.ghidra.storage.InferenceStorage;
import com.zenyard.decompai.ghidra.storage.SyncStatus;
import com.zenyard.decompai.ghidra.storage.SyncStatusStorage;
import com.zenyard.decompai.ghidra.status.StatusBarManager;
import com.zenyard.decompai.ghidra.util.FunctionSerializer;
import com.zenyard.decompai.ghidra.util.GlobalVariableSerializer;
import com.zenyard.decompai.ghidra.util.ObjectGraph;
import com.zenyard.decompai.ghidra.util.ObjectGraph.Symbol;
import com.zenyard.decompai.ghidra.util.ObjectHasher;
import com.zenyard.decompai.ghidra.util.ObjectReader;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Background task to scan database for objects and queue revisions.
 * Waits for UPLOAD_ORIGINAL_FILES_COMPLETE or INITIAL_DIALOG_CONFIRMED events.
 * Publishes REVISIONS_QUEUED event with revisions in payload.
 * Shows progress via status bar instead of modal dialog.
 * 
 * NOTE: mirrors decompai_ida/queue_revisions_task.py
 */
public class QueueRevisionsTask extends Task implements EventConsumer, EventProducer {
    
    private static final int MAX_OBJECTS_IN_REVISION = 100; // Configurable
    private static final String TASK_ID = "queue_revisions";
    private static final int STATUS_BAR_PRIORITY = com.zenyard.decompai.ghidra.status.StatusBarPriorities.QUEUE_REVISIONS;
    
    private final PluginTool tool;
    private final Program program;
    private final StatusBarManager statusBarManager;
    private final EventDispatcher eventDispatcher;
    private final boolean forceQueue;
    private List<Revision> revisions = new ArrayList<>();
    
    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean readyToQueue = false;
    private volatile boolean shouldStop = false;
    
    public QueueRevisionsTask(PluginTool tool, Program program, StatusBarManager statusBarManager, EventDispatcher eventDispatcher) {
        this(tool, program, statusBarManager, eventDispatcher, false);
    }

    public QueueRevisionsTask(PluginTool tool, Program program, StatusBarManager statusBarManager,
        EventDispatcher eventDispatcher, boolean forceQueue) {
        super("Queue Revisions", true, true, false); // canCancel=true, hasProgress=true, isModal=false (background task, uses status bar)
        this.tool = tool;
        this.program = program;
        this.statusBarManager = statusBarManager;
        this.eventDispatcher = eventDispatcher;
        this.forceQueue = forceQueue;
    }
    
    @Override
    public Set<DecompaiEvent.EventType> getSubscribedEventTypes() {
        Set<DecompaiEvent.EventType> types = new HashSet<>();
        types.add(DecompaiEvent.EventType.UPLOAD_ORIGINAL_FILES_COMPLETE);
        types.add(DecompaiEvent.EventType.INITIAL_DIALOG_CONFIRMED);
        types.add(DecompaiEvent.EventType.PROGRAM_DEACTIVATED);
        return types;
    }
    
    @Override
    public void handleEvent(DecompaiEvent event) {
        if (event.getType() == DecompaiEvent.EventType.UPLOAD_ORIGINAL_FILES_COMPLETE 
            || event.getType() == DecompaiEvent.EventType.INITIAL_DIALOG_CONFIRMED) {
            synchronized (waitLock) {
                readyToQueue = true;
                waitLock.notify();
            }
        } else if (event.getType() == DecompaiEvent.EventType.PROGRAM_DEACTIVATED) {
            synchronized (waitLock) {
                shouldStop = true;
                waitLock.notify(); // Wake up any waiting threads
            }
        }
    }
    
    @Override
    public void publishEvent(DecompaiEvent event) {
        if (eventDispatcher != null) {
            eventDispatcher.publish(event);
        }
    }
    
    /**
     * Get the list of revisions that were queued.
     * @return List of revisions
     */
    public List<Revision> getRevisions() {
        return revisions;
    }
    
    @Override
    public void run(TaskMonitor monitor) {
        // Subscribe to events
        if (eventDispatcher != null) {
            eventDispatcher.subscribe(this);
        }
        
        try {
            DecompaiProgramProperties props = new DecompaiProgramProperties(program);

            // Check if prerequisites are already met
            String originalFilesUploaded = props.getString("original_files_uploaded");
            String initialDialogConfirmed = props.getString("asked_initial_questions");
            if ("true".equals(originalFilesUploaded) || "true".equals(initialDialogConfirmed)) {
                readyToQueue = true;
            }

            // Check if already queued
            String uploaded = props.getString("initial_upload_complete");
            if ("true".equals(uploaded) && !forceQueue) {
                // Already uploaded, skip
                return;
            }
            
            // Wait for UPLOAD_ORIGINAL_FILES_COMPLETE or INITIAL_DIALOG_CONFIRMED event
            synchronized (waitLock) {
                while (!readyToQueue && !monitor.isCancelled() && !shouldStop) {
                    // Re-check properties periodically
                    originalFilesUploaded = props.getString("original_files_uploaded");
                    initialDialogConfirmed = props.getString("asked_initial_questions");
                    if ("true".equals(originalFilesUploaded) || "true".equals(initialDialogConfirmed)) {
                        readyToQueue = true;
                        break;
                    }
                    
                    try {
                        waitLock.wait(1000); // Wait up to 1 second, then check again
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
            
            if (monitor.isCancelled() || shouldStop) {
                return;
            }
            
            final boolean isInitialUpload = !"true".equals(uploaded);
            
            // Now that we're ready to process, launch a modal task to show the dialog
            // This ensures the dialog only appears when actual work begins
            // Must launch from EDT for modal dialogs to work correctly
            javax.swing.SwingUtilities.invokeLater(() -> {
                ProcessRevisionsTask processTask = new ProcessRevisionsTask(
                    tool, program, statusBarManager, isInitialUpload, revisions, eventDispatcher, this);
                new ghidra.util.task.TaskLauncher(processTask, tool.getActiveWindow());
            });
            
            // Processing is now handled by ProcessRevisionsTask, which will publish events
            
        } catch (Exception e) {
            Msg.showError(this, tool.getActiveWindow(), "Queue Error",
                "Failed to queue revisions: " + e.getMessage(), e);
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(TASK_ID);
            }
            throw new RuntimeException("Failed to queue revisions", e);
        } finally {
            // Unsubscribe from events
            if (eventDispatcher != null) {
                eventDispatcher.unsubscribe(this);
            }
            
            // Unregister status bar
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(TASK_ID);
            }
        }
    }
    
    /**
     * Get all dirty object symbols (functions and global variables).
     */
    List<Symbol> getDirtyObjectSymbols(TaskMonitor monitor, SyncStatusStorage syncStatusStorage) {
        Set<Symbol> dirtySymbols = new HashSet<>();
        List<Address> dirtyAddresses = syncStatusStorage.getDirtyAddresses();
        if (dirtyAddresses.isEmpty()) {
            DecompaiProgramProperties props = new DecompaiProgramProperties(program);
            String databaseDirty = props.getString("database_dirty");
            if ("true".equals(databaseDirty)) {
                for (Symbol symbol : ObjectReader.getAllObjectSymbols(program)) {
                    if (monitor.isCancelled()) {
                        break;
                    }

                    if (syncStatusStorage.isDirty(symbol.getAddress())) {
                        dirtySymbols.add(symbol);
                        syncStatusStorage.markDirty(symbol.getAddress());
                    }
                }

                return new ArrayList<>(dirtySymbols);
            }
        }

        for (Address address : dirtyAddresses) {
            if (monitor.isCancelled()) {
                break;
            }

            ObjectReader.getObjectSymbolForAddress(program, address)
                .ifPresent(dirtySymbols::add);
        }

        return new ArrayList<>(dirtySymbols);
    }
    
    /**
     * Buffer an object if it has changed.
     * Applies pending inferences, reads object, computes hash, and compares.
     */
    void bufferObjectIfChanged(Address address, List<BufferedObject> buffer, TaskMonitor monitor, SyncStatusStorage syncStatusStorage, PendingInferenceManager pendingInferenceManager) {
        Optional<SyncStatus> syncStatus = syncStatusStorage.getSyncStatus(address);
        SyncStatus status = syncStatus.orElse(new SyncStatus());
        
        // Apply pending inferences before reading
        pendingInferenceManager.applyPendingInferences(address);
        
        // Read object (function or global variable)
        ModelObject obj;
        try {
            FunctionManager funcManager = program.getFunctionManager();
            Function function = funcManager.getFunctionAt(address);
            
            if (function != null) {
                // It's a function
                com.zenyard.decompai.ghidra.api.generated.model.Function apiFunction = 
                    FunctionSerializer.serializeFunction(program, function, 0);
                obj = new ModelObject();
                obj.setActualInstance(apiFunction);
            } else {
                // It's a global variable
                GlobalVariable gv = GlobalVariableSerializer.serializeGlobalVariable(program, address, 0);
                obj = new ModelObject();
                obj.setActualInstance(gv);
            }
        } catch (Exception e) {
            Msg.warn(this, "Can't read object at " + address + ": " + e.getMessage());
            // Mark clean so we don't try again until next change
            syncStatusStorage.setSyncStatus(address, status.withDirty(false));
            return;
        }
        
        // Compute hash
        String currentHash = ObjectHasher.hashObject(obj);
        
        // Compare with stored hash
        Optional<String> uploadedHash = status.getUploadedHash();
        if (uploadedHash.isPresent() && uploadedHash.get().equals(currentHash)) {
            // Object unchanged
            Msg.debug(this, "Object unchanged at " + address);
            syncStatusStorage.setSyncStatus(address, status.withDirty(false));
            return;
        }
        
        // Object changed or new - buffer for upload
        buffer.add(new BufferedObject(address, obj, currentHash));
        Msg.debug(this, "Object buffered for revision at " + address);
    }
    
    /**
     * Flush a revision and return it.
     */
    Revision flushRevision(List<BufferedObject> bufferedObjects, boolean isInitialUpload, SyncStatusStorage syncStatusStorage) {
        if (bufferedObjects.isEmpty()) {
            return null;
        }
        
        // Convert to ModelObject list
        List<ModelObject> objects = new ArrayList<>();
        for (BufferedObject buffered : bufferedObjects) {
            objects.add(buffered.object);
        }
        
        Revision revision = new Revision(objects, isInitialUpload);
        
        // Mark all objects as uploaded and clean
        for (BufferedObject buffered : bufferedObjects) {
            SyncStatus newStatus = new SyncStatus(
                Optional.of(buffered.hash),
                false // not dirty
            );
            syncStatusStorage.setSyncStatus(buffered.address, newStatus);
            Msg.debug(this, "Object marked clean at " + buffered.address);
        }
        
        Msg.info(this, "DecompAI: Queued revision with " + objects.size() + " objects");
        return revision;
    }
    
    /**
     * Inner task that performs the actual revision processing with modal dialog.
     * This task is launched only when processing actually begins.
     */
    private static class ProcessRevisionsTask extends Task {
        private final Program program;
        private final StatusBarManager statusBarManager;
        private final boolean isInitialUpload;
        private final List<Revision> revisions;
        private final EventDispatcher eventDispatcher;
        private final QueueRevisionsTask parentTask;
        
        public ProcessRevisionsTask(PluginTool tool, Program program, StatusBarManager statusBarManager,
                                   boolean isInitialUpload, List<Revision> revisions,
                                   EventDispatcher eventDispatcher, QueueRevisionsTask parentTask) {
            super("Zenyard is Preparing", true, true, true); // canCancel=true, hasProgress=true, isModal=true
            this.program = program;
            this.statusBarManager = statusBarManager;
            this.isInitialUpload = isInitialUpload;
            this.revisions = revisions;
            this.eventDispatcher = eventDispatcher;
            this.parentTask = parentTask;
        }
        
        @Override
        public void run(TaskMonitor monitor) {
            // Register with status bar
            if (statusBarManager != null) {
                statusBarManager.registerTask(TASK_ID, STATUS_BAR_PRIORITY);
                statusBarManager.updateTaskStatus(TASK_ID, "Preparing data for analysis...", null, true);
            }
            
            SyncStatusStorage syncStatusStorage = new SyncStatusStorage(program);
            if (isInitialUpload && syncStatusStorage.getDirtyAddresses().isEmpty()) {
                initializeSyncStatus(program);
            }
            
            // Initialize pending inference manager
            InferenceStorage inferenceStorage = new InferenceStorage(program);
            FunctionOverviewAnnotator overviewAnnotator = new FunctionOverviewAnnotator();
            InferenceApplier inferenceApplier = new InferenceApplier(overviewAnnotator, inferenceStorage);
            PendingInferenceManager pendingInferenceManager = new PendingInferenceManager(program, inferenceStorage, inferenceApplier);
            
            // Phase 1: Scan for dirty objects
            monitor.setMessage("Scanning database for objects...");
            List<Symbol> dirtySymbols = parentTask.getDirtyObjectSymbols(monitor, syncStatusStorage);
            
            // Phase 2: Topological ordering
            List<Address> orderedAddresses = ObjectGraph.getObjectsInApproxTopoOrder(program, dirtySymbols);
            
            // Initialize progress monitor for processing phase
            monitor.setMessage("Zenyard is preparing your data for analysis — this may take a little while...");
            monitor.initialize(orderedAddresses.size());
            monitor.setIndeterminate(false);
            
            // Phase 3: Process objects
            List<BufferedObject> buffer = new ArrayList<>();
            int processed = 0;
            
            for (Address address : orderedAddresses) {
                if (monitor.isCancelled()) {
                    return;
                }
                
                try {
                    parentTask.bufferObjectIfChanged(address, buffer, monitor, syncStatusStorage, pendingInferenceManager);
                    
                    // Flush if buffer is full
                    if (buffer.size() >= MAX_OBJECTS_IN_REVISION) {
                        Revision revision = parentTask.flushRevision(buffer, isInitialUpload, syncStatusStorage);
                        revisions.add(revision);
                        buffer.clear();
                    }
                    
                    processed++;
                    monitor.setProgress(processed);
                    
                    // Update message with percentage
                    int percentage = (int)(100.0 * processed / orderedAddresses.size());
                    monitor.setMessage("Zenyard is preparing your data for analysis — this may take a little while (" + percentage + "%)");
                } catch (Exception e) {
                    Msg.warn(this, "Failed to process object at " + address + ": " + e.getMessage());
                    // Mark clean to avoid retry loops
                    syncStatusStorage.markClean(address);
                }
            }
            
            // Flush remaining objects
            if (!buffer.isEmpty()) {
                Revision revision = parentTask.flushRevision(buffer, isInitialUpload, syncStatusStorage);
                revisions.add(revision);
            }
            
            // Mark queuing as complete
            DecompaiProgramProperties props = new DecompaiProgramProperties(program);
            props.setString("queueing_complete", "true");
            
            Msg.info(this, "DecompAI: Queued " + processed + " objects for upload (" + revisions.size() + " revision(s))");
            
            // Update status bar with final status
            if (statusBarManager != null) {
                statusBarManager.updateTaskStatus(TASK_ID, "Queued " + revisions.size() + " revision(s)", 100, false);
            }
            
            // Publish REVISIONS_QUEUED event with revisions in payload
            Map<String, Object> payload = new HashMap<>();
            payload.put("revisions", revisions);
            payload.put("revisionCount", revisions.size());
            payload.put("isInitialUpload", isInitialUpload);
            if (eventDispatcher != null) {
                eventDispatcher.publish(new DecompaiEvent(DecompaiEvent.EventType.REVISIONS_QUEUED, "Queue Revisions", payload));
            }
            
            // If initial upload, also publish INITIAL_UPLOAD_COMPLETE
            if (isInitialUpload) {
                if (eventDispatcher != null) {
                    eventDispatcher.publish(new DecompaiEvent(DecompaiEvent.EventType.INITIAL_UPLOAD_COMPLETE, "Queue Revisions"));
                }
            }
            
            // Unregister from status bar when done - this allows other tasks (like download) to be displayed
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(TASK_ID);
            }
        }
    }

    private static void initializeSyncStatus(Program program) {
        if (program == null) {
            return;
        }
        SyncStatusStorage syncStatusStorage = new SyncStatusStorage(program);
        List<Symbol> symbols = ObjectReader.getAllObjectSymbols(program);
        for (Symbol symbol : symbols) {
            syncStatusStorage.markDirty(symbol.getAddress());
        }
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        props.setString("database_dirty", "true");
    }
    
    /**
     * Buffered object with address, object, and hash.
     */
    private static class BufferedObject {
        final Address address;
        final ModelObject object;
        final String hash;
        
        BufferedObject(Address address, ModelObject object, String hash) {
            this.address = address;
            this.object = object;
            this.hash = hash;
        }
    }
    
    /**
     * Revision data class.
     */
    public static class Revision {
        private final List<ModelObject> objects;
        private final boolean isInitialAnalysis;
        
        public Revision(List<ModelObject> objects, boolean isInitialAnalysis) {
            this.objects = objects;
            this.isInitialAnalysis = isInitialAnalysis;
        }
        
        public List<ModelObject> getObjects() {
            return objects;
        }
        
        public boolean isInitialAnalysis() {
            return isInitialAnalysis;
        }
    }
    
    /**
     * Simple queue for revisions.
     */
    public static class RevisionQueue {
        private final List<Revision> queue = new ArrayList<>();
        
        public synchronized void enqueue(Revision revision) {
            queue.add(revision);
        }
        
        public synchronized Revision dequeue() {
            if (queue.isEmpty()) {
                return null;
            }
            return queue.remove(0);
        }
        
        public synchronized int size() {
            return queue.size();
        }
        
        public synchronized boolean isEmpty() {
            return queue.isEmpty();
        }
    }
}
