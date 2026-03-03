package com.zenyard.ghidra.upload;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.zenyard.ghidra.api.generated.model.GlobalVariable;
import com.zenyard.ghidra.api.generated.model.ModelObject;
import com.zenyard.ghidra.ZenyardService;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.tasks.EventAwareTask;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.storage.SyncStatus;
import com.zenyard.ghidra.storage.SyncStatusStorage;
import com.zenyard.ghidra.status.StatusBarManager;
import com.zenyard.ghidra.status.StatusBarPriorities;
import com.zenyard.ghidra.usage.UsageState;
import com.zenyard.ghidra.util.FunctionSerializer;
import com.zenyard.ghidra.util.GlobalVariableSerializer;
import com.zenyard.ghidra.util.ObjectGraph;
import com.zenyard.ghidra.util.ObjectGraph.Symbol;
import com.zenyard.ghidra.util.ObjectHasher;
import com.zenyard.ghidra.util.ObjectReader;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * Background task to scan database for objects and queue revisions.
 * Waits for UPLOAD_ORIGINAL_FILES_COMPLETE or INITIAL_DIALOG_CONFIRMED events.
 * Publishes REVISIONS_QUEUED event with revisions in payload.
 * Shows a modal progress dialog while preparing revisions, with status bar updates.
 * 
 * NOTE: mirrors zenyard_ida/queue_revisions_task.py
 */
public class QueueRevisionsTask extends EventAwareTask {
    
    private static final int MAX_OBJECTS_IN_REVISION = 100; // Configurable
    private static final String TASK_ID = "queue_revisions";
    private static final String PREPARING_MESSAGE =
        "Zenyard is preparing your data for analysis — this may take a little while";
    private static final int PREPARING_DIALOG_WIDTH = 640;
    private static final int STATUS_BAR_PRIORITY = StatusBarPriorities.QUEUE_REVISIONS;
    
    private final PluginTool tool;
    private final Program program;
    private final StatusBarManager statusBarManager;
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
        super("Queue Revisions", true, true, false, eventDispatcher);
        this.tool = tool;
        this.program = program;
        this.statusBarManager = statusBarManager;
        this.forceQueue = forceQueue;
    }
    
    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        Set<ZenyardEvent.EventType> types = new HashSet<>();
        types.add(ZenyardEvent.EventType.UPLOAD_ORIGINAL_FILES_COMPLETE);
        types.add(ZenyardEvent.EventType.INITIAL_DIALOG_CONFIRMED);
        types.add(ZenyardEvent.EventType.PROGRAM_DEACTIVATED);
        types.add(ZenyardEvent.EventType.BINARY_PAUSED_UPDATED);
        return types;
    }
    
    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.UPLOAD_ORIGINAL_FILES_COMPLETE 
            || event.getType() == ZenyardEvent.EventType.INITIAL_DIALOG_CONFIRMED) {
            synchronized (waitLock) {
                readyToQueue = true;
                waitLock.notify();
            }
        } else if (event.getType() == ZenyardEvent.EventType.PROGRAM_DEACTIVATED) {
            synchronized (waitLock) {
                shouldStop = true;
                waitLock.notify();
            }
        } else if (event.getType() == ZenyardEvent.EventType.BINARY_PAUSED_UPDATED) {
            Boolean paused = event.getPayloadValue("paused", Boolean.class);
            if (Boolean.TRUE.equals(paused)) {
                synchronized (waitLock) {
                    shouldStop = true;
                    waitLock.notify();
                }
            }
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
    protected void doRun(TaskMonitor monitor) {
        try {
            if (isUsageBlocked()) {
                return;
            }
            if (isBinaryPaused()) {
                return;
            }
            ZenyardProgramProperties props = new ZenyardProgramProperties(program);

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

            if (isUsageBlocked()) {
                return;
            }
            
            final boolean isInitialUpload = !"true".equals(uploaded);
            
            // Launch processing task with a modal dialog and progress bar
            ProcessRevisionsTask processTask = new ProcessRevisionsTask(
                program, statusBarManager, isInitialUpload, revisions, getEventDispatcher(), this);
            new TaskLauncher(processTask, tool.getActiveWindow(), 0, PREPARING_DIALOG_WIDTH);
            
            // Processing is now handled by ProcessRevisionsTask, which will publish events
            
        } catch (Exception e) {
            Msg.showError(this, tool.getActiveWindow(), "Queue Error",
                "Failed to queue revisions: " + e.getMessage(), e);
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(TASK_ID);
            }
            throw new RuntimeException("Failed to queue revisions", e);
        } finally {
            // Unregister status bar
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(TASK_ID);
            }
        }
    }

    private boolean isUsageBlocked() {
        ZenyardService services = ZenyardService.getInstanceForTool(tool);
        if (services == null) {
            return false;
        }
        UsageState usageState = services.getUsageState();
        if (usageState != null && usageState.isBlocked()) {
            UsageState.showBlockedDialog(tool.getActiveWindow(), usageState);
            return true;
        }
        return false;
    }

    private boolean isBinaryPaused() {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        return "true".equals(props.getString("binary_paused"));
    }
    
    /**
     * Get all dirty object symbols (functions and global variables).
     */
    List<Symbol> getDirtyObjectSymbols(TaskMonitor monitor, SyncStatusStorage syncStatusStorage) {
        Set<Symbol> dirtySymbols = new HashSet<>();
        List<Address> dirtyAddresses = syncStatusStorage.getDirtyAddresses();
        if (dirtyAddresses.isEmpty()) {
            ZenyardProgramProperties props = new ZenyardProgramProperties(program);
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
     * Reads object, computes hash, and compares.
     */
    void bufferObjectIfChanged(Address address, List<BufferedObject> buffer, TaskMonitor monitor, SyncStatusStorage syncStatusStorage) {
        Optional<SyncStatus> syncStatus = syncStatusStorage.getSyncStatus(address);
        SyncStatus status = syncStatus.orElse(new SyncStatus());

        // Read object (function or global variable)
        ModelObject obj;
        try {
            FunctionManager funcManager = program.getFunctionManager();
            Function function = funcManager.getFunctionAt(address);
            
            if (function != null) {
                // It's a function
                com.zenyard.ghidra.api.generated.model.Function apiFunction = 
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
        List<QueuedObject> queuedObjects = new ArrayList<>();
        for (BufferedObject buffered : bufferedObjects) {
            objects.add(buffered.object);
            queuedObjects.add(new QueuedObject(buffered.address, buffered.hash));
        }
        
        Revision revision = new Revision(objects, queuedObjects, isInitialUpload);

        Msg.info(this, "Zenyard: Queued revision with " + objects.size() + " objects");
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

        public ProcessRevisionsTask(Program program, StatusBarManager statusBarManager,
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
            if (isInitialUpload) {
                initializeSyncStatus(program);
            }
            
            // Phase 1: Scan for dirty objects
            monitor.setMessage("Scanning database for objects...");
            List<Symbol> dirtySymbols = parentTask.getDirtyObjectSymbols(monitor, syncStatusStorage);
            
            // Phase 2: Topological ordering
            List<Address> orderedAddresses = ObjectGraph.getObjectsInApproxTopoOrder(program, dirtySymbols);
            
            // Initialize progress monitor for processing phase
            monitor.setMessage(PREPARING_MESSAGE + "...");
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
                    parentTask.bufferObjectIfChanged(address, buffer, monitor, syncStatusStorage);
                    
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
                    monitor.setMessage(PREPARING_MESSAGE + " (" + percentage + "%)");
                } catch (Exception e) {
                    Msg.warn(this, "Failed to process object at " + address + ": " + e.getMessage());
                }
            }
            
            // Flush remaining objects
            if (!buffer.isEmpty()) {
                Revision revision = parentTask.flushRevision(buffer, isInitialUpload, syncStatusStorage);
                revisions.add(revision);
            }

            // Only the last revision requests global analysis (mirrors IDA behavior).
            if (!revisions.isEmpty()) {
                int lastIdx = revisions.size() - 1;
                Revision last = revisions.get(lastIdx);
                revisions.set(lastIdx, last.withPerformGlobalAnalysis(true));
                Msg.info(this, "Zenyard: Marked last revision for global analysis ("
                    + (lastIdx + 1) + "/" + revisions.size()
                    + ", objects=" + (last.getObjects() != null ? last.getObjects().size() : 0)
                    + "): performGlobalAnalysis=true");
            }
            
            // Mark queuing as complete
            ZenyardProgramProperties props = new ZenyardProgramProperties(program);
            props.setString("queueing_complete", "true");
            if (revisions.isEmpty()) {
                // No changed objects were found after hash comparison.
                props.setString("database_dirty", "false");
                props.setString("changes_detected", "false");
            }
            
            Msg.info(this, "Zenyard: Queued " + processed + " objects for upload (" + revisions.size() + " revision(s))");
            
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
                eventDispatcher.publish(new ZenyardEvent(ZenyardEvent.EventType.REVISIONS_QUEUED, "Queue Revisions", payload));
            }
            
            // INITIAL_UPLOAD_COMPLETE is published only by UploadRevisionsTask after upload finishes,
            // so the "Zenyard will analyze in the background" dialog shows only when upload is truly complete.
            
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
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
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
     * Queued object metadata (used to clear dirty list after upload).
     */
    public static class QueuedObject {
        private final Address address;
        private final String hash;

        public QueuedObject(Address address, String hash) {
            this.address = address;
            this.hash = hash;
        }

        public Address getAddress() {
            return address;
        }

        public String getHash() {
            return hash;
        }
    }
    
    /**
     * Revision data class.
     */
    public static class Revision {
        private final List<ModelObject> objects;
        private final List<QueuedObject> queuedObjects;
        private final boolean isInitialAnalysis;
        private final boolean performGlobalAnalysis;
        
        public Revision(List<ModelObject> objects, List<QueuedObject> queuedObjects, boolean isInitialAnalysis) {
            this(objects, queuedObjects, isInitialAnalysis, false);
        }

        public Revision(List<ModelObject> objects, List<QueuedObject> queuedObjects,
                boolean isInitialAnalysis, boolean performGlobalAnalysis) {
            this.objects = objects;
            this.queuedObjects = queuedObjects;
            this.isInitialAnalysis = isInitialAnalysis;
            this.performGlobalAnalysis = performGlobalAnalysis;
        }
        
        public List<ModelObject> getObjects() {
            return objects;
        }

        public List<QueuedObject> getQueuedObjects() {
            return queuedObjects;
        }
        
        public boolean isInitialAnalysis() {
            return isInitialAnalysis;
        }

        public boolean isPerformGlobalAnalysis() {
            return performGlobalAnalysis;
        }

        public Revision withPerformGlobalAnalysis(boolean performGlobalAnalysis) {
            return new Revision(objects, queuedObjects, isInitialAnalysis, performGlobalAnalysis);
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
