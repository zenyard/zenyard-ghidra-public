package com.zenyard.ghidra.upload;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import com.zenyard.ghidra.api.generated.ApiException;
import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.model.AddObjectsToCurrentRevisionParams;
import com.zenyard.ghidra.api.generated.model.CreateRevisionParams;
import com.zenyard.ghidra.api.generated.model.FinishAndAnalyzeCurrentRevisionBody;
import com.zenyard.ghidra.api.generated.model.Function;
import com.zenyard.ghidra.api.generated.model.GlobalVariable;
import com.zenyard.ghidra.api.generated.model.ModelObject;
import com.zenyard.ghidra.api.generated.model.Range;
import com.zenyard.ghidra.api.generated.model.Section;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.tasks.StatusBarAwareTask;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.storage.SyncStatus;
import com.zenyard.ghidra.storage.SyncStatusStorage;
import com.zenyard.ghidra.status.StatusBarManager;
import com.zenyard.ghidra.status.StatusBarPriorities;
import com.zenyard.ghidra.status.StatusBarState;
import com.zenyard.ghidra.status.StatusBarViewModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Background task to upload revisions with status bar progress.
 * Waits for REVISIONS_QUEUED event, then uploads revisions.
 * Publishes REVISIONS_UPLOADED or INITIAL_UPLOAD_COMPLETE events.
 * 
 * NOTE: mirrors zenyard_ida/upload_revisions_task.py
 */
public class UploadRevisionsTask extends StatusBarAwareTask {
    
    private static final int MAX_UPLOAD_BYTES = 10 * 1024 * 1024; // 10MB
    private static final String TASK_ID = "upload_revisions";
    private static final int STATUS_BAR_PRIORITY = StatusBarPriorities.UPLOAD_REVISIONS;
    private static final ConcurrentHashMap<Program, AtomicBoolean> RUNNING_UPLOADS = new ConcurrentHashMap<>();
    
    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final Program program;
    
    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean revisionsQueued = false;
    private volatile boolean shouldStop = false;
    private volatile TaskMonitor runningMonitor;
    private List<QueueRevisionsTask.Revision> revisions = new ArrayList<>();
    private UUID binaryId = null;
    private boolean isInitialUpload = false;
    private volatile boolean binaryIdAvailable = false;
    
    public UploadRevisionsTask(PluginTool tool, BinariesApi binariesApi,
                               StatusBarManager statusBarManager, Program program, EventDispatcher eventDispatcher) {
        super("Upload Revisions", true, false, false, eventDispatcher, statusBarManager, TASK_ID, STATUS_BAR_PRIORITY);
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.program = program;
    }
    
    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        Set<ZenyardEvent.EventType> types = new HashSet<>();
        types.add(ZenyardEvent.EventType.REVISIONS_QUEUED);
        types.add(ZenyardEvent.EventType.BINARY_ID_AVAILABLE);
        types.add(ZenyardEvent.EventType.PROGRAM_DEACTIVATED);
        types.add(ZenyardEvent.EventType.BINARY_PAUSED_UPDATED);
        return types;
    }
    
    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.REVISIONS_QUEUED) {
            Msg.info(this, "UploadRevisionsTask: Received REVISIONS_QUEUED event");
            @SuppressWarnings("unchecked")
            List<QueueRevisionsTask.Revision> eventRevisions = 
                (List<QueueRevisionsTask.Revision>) event.getPayloadValue("revisions");
            Boolean eventIsInitialUpload = (Boolean) event.getPayloadValue("isInitialUpload");
            
            if (eventRevisions != null) {
                synchronized (waitLock) {
                    this.revisions = eventRevisions;
                    this.isInitialUpload = eventIsInitialUpload != null ? eventIsInitialUpload : false;
                    this.revisionsQueued = true;
                    waitLock.notify();
                    Msg.info(this, "UploadRevisionsTask: Set revisionsQueued=true, revisions count: " + eventRevisions.size());
                }
            } else {
                // Fallback: check if queueing_complete indicates revisions were queued
                // Log warning but don't block - let the wait loop check properties
                Msg.warn(this, "REVISIONS_QUEUED event received but revisions payload is null");
                // Still set revisionsQueued to true if queueing_complete property indicates it
                ZenyardProgramProperties props = new ZenyardProgramProperties(program);
                String queueingComplete = props.getString("queueing_complete");
                if ("true".equals(queueingComplete)) {
                    synchronized (waitLock) {
                        this.isInitialUpload = eventIsInitialUpload != null ? eventIsInitialUpload : false;
                        this.revisionsQueued = true;
                        waitLock.notify();
                        Msg.info(this, "UploadRevisionsTask: Set revisionsQueued=true based on queueing_complete property");
                    }
                }
            }
        } else if (event.getType() == ZenyardEvent.EventType.BINARY_ID_AVAILABLE) {
            UUID eventBinaryId = event.getPayloadValue("binaryId", UUID.class);
            if (eventBinaryId != null) {
                synchronized (waitLock) {
                    this.binaryId = eventBinaryId;
                    this.binaryIdAvailable = true;
                    waitLock.notify();
                }
            } else {
                // Fallback: get from properties if event payload is null
                ZenyardProgramProperties props = new ZenyardProgramProperties(program);
                String binaryIdStr = props.getString("binary_id");
                if (binaryIdStr != null && !binaryIdStr.isEmpty()) {
                    try {
                        synchronized (waitLock) {
                            this.binaryId = UUID.fromString(binaryIdStr);
                            this.binaryIdAvailable = true;
                            waitLock.notify();
                            Msg.info(this, "UploadRevisionsTask: Retrieved binaryId from properties in BINARY_ID_AVAILABLE handler: " + binaryId);
                        }
                    } catch (IllegalArgumentException e) {
                        Msg.warn(this, "UploadRevisionsTask: Invalid binary_id format in properties: " + binaryIdStr);
                    }
                }
            }
        } else if (event.getType() == ZenyardEvent.EventType.PROGRAM_DEACTIVATED) {
            Msg.info(this, "UploadRevisionsTask: Received PROGRAM_DEACTIVATED event");
            if (runningMonitor != null) {
                runningMonitor.cancel();
            }
            synchronized (waitLock) {
                shouldStop = true;
                waitLock.notify();
            }
        } else if (event.getType() == ZenyardEvent.EventType.BINARY_PAUSED_UPDATED) {
            Boolean paused = event.getPayloadValue("paused", Boolean.class);
            if (Boolean.TRUE.equals(paused)) {
                Msg.info(this, "UploadRevisionsTask: Binary paused, stopping upload");
                if (runningMonitor != null) {
                    runningMonitor.cancel();
                }
                synchronized (waitLock) {
                    shouldStop = true;
                    waitLock.notify();
                }
            }
        }
    }
    
    @Override
    protected void doRun(TaskMonitor monitor) {
        runningMonitor = monitor;
        AtomicBoolean runningFlag = RUNNING_UPLOADS.computeIfAbsent(program, key -> new AtomicBoolean(false));
        if (!runningFlag.compareAndSet(false, true)) {
            Msg.warn(this, "UploadRevisionsTask: Another upload task is already running for this program. Skipping.");
            return;
        }
        try {
            try {
            // Early exit if binary is paused
            ZenyardProgramProperties props = new ZenyardProgramProperties(program);
            if ("true".equals(props.getString("binary_paused"))) {
                Msg.info(this, "UploadRevisionsTask: Binary is paused, skipping upload");
                return;
            }

            // Get binary ID from properties
            String binaryIdStr = props.getString("binary_id");
            if (binaryIdStr != null && !binaryIdStr.isEmpty()) {
                try {
                    this.binaryId = UUID.fromString(binaryIdStr);
                    this.binaryIdAvailable = true;
                } catch (IllegalArgumentException e) {
                    // Invalid UUID format
                }
            }
            
            // Wait for REVISIONS_QUEUED event
            Msg.info(this, "UploadRevisionsTask: Waiting for REVISIONS_QUEUED event...");
            synchronized (waitLock) {
                while ((!revisionsQueued || !binaryIdAvailable) && !monitor.isCancelled() && !shouldStop) {
                    try {
                        waitLock.wait(1000); // Wait up to 1 second, then check again
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    if (!binaryIdAvailable) {
                        String binaryIdRetry = props.getString("binary_id");
                        if (binaryIdRetry != null && !binaryIdRetry.isEmpty()) {
                            try {
                                this.binaryId = UUID.fromString(binaryIdRetry);
                                this.binaryIdAvailable = true;
                            } catch (IllegalArgumentException e) {
                                // Invalid UUID format
                            }
                        }
                    }
                }
            }
            
            Msg.info(this, "UploadRevisionsTask: Exited wait loop, revisionsQueued=" + revisionsQueued 
                + ", revisions.size()=" + revisions.size() + ", shouldStop=" + shouldStop);
            
            // Re-check binaryId from properties in case it was set after we started waiting
            if (binaryId == null) {
                String binaryIdStrRetry = props.getString("binary_id");
                if (binaryIdStrRetry != null && !binaryIdStrRetry.isEmpty()) {
                    try {
                        this.binaryId = UUID.fromString(binaryIdStrRetry);
                        this.binaryIdAvailable = true;
                        Msg.info(this, "UploadRevisionsTask: Retrieved binaryId from properties: " + binaryId);
                    } catch (IllegalArgumentException e) {
                        Msg.error(this, "UploadRevisionsTask: Invalid binary_id format: " + binaryIdStrRetry);
                    }
                }
            }
            
            if (binaryId == null) {
                Msg.error(this, "UploadRevisionsTask: Cannot upload - binaryId is null. Waiting for BINARY_ID_AVAILABLE event.");
                return;
            }
            
            if (revisions.isEmpty()) {
                Msg.warn(this, "UploadRevisionsTask: Cannot upload - revisions list is empty");
                // During shutdown PROGRAM_DEACTIVATED may fire after queue state is cleared.
                // Clearing rerun UI state is best-effort; never try to start new transactions
                // on a terminated/closed program database.
                if (!monitor.isCancelled() && !shouldStop && program != null && !program.isClosed()) {
                    clearRerunStateAfterSync();
                }
                return;
            }
            
            if (monitor.isCancelled() || shouldStop) {
                Msg.info(this, "UploadRevisionsTask: Cancelled or stopped, aborting upload");
                return;
            }
            
            Msg.info(this, "UploadRevisionsTask: Starting upload of " + revisions.size() + " revision(s) for binaryId: " + binaryId);
            
            runWithStatusBar(() -> {
                StatusBarManager statusBarManager = getStatusBarManager();
                SyncStatusStorage syncStatusStorage = new SyncStatusStorage(program);

                int currentRevision = getCurrentRevision();
                int totalRevisions = revisions.size();
                int startRevision = currentRevision;

                for (int revIndex = 0; revIndex < revisions.size(); revIndex++) {
                    if (monitor.isCancelled() || shouldStop) {
                        return;
                    }

                    QueueRevisionsTask.Revision revision = revisions.get(revIndex);
                    currentRevision++;

                    // Calculate progress percentage
                    int uploadProgress = 0;
                    if (totalRevisions > 0) {
                        uploadProgress = (int)((revIndex / (double)totalRevisions) * 100);
                    }
                    String uploadMessage = "Uploading revision " + currentRevision + "/" 
                        + (startRevision + totalRevisions) + " (" + uploadProgress + "%)";
                    if (statusBarManager != null) {
                        statusBarManager.updateTaskStatus(TASK_ID, uploadMessage, uploadProgress, false);
                    }
                
                // Create revision
                CreateRevisionParams createParams = new CreateRevisionParams();
                createParams.setNumber(currentRevision);
                CompletableFuture.supplyAsync(() -> {
                    try {
                        binariesApi.createRevision(binaryId, createParams);
                        return null;
                    } catch (ApiException e) {
                        throw new RuntimeException(e);
                    }
                }).get();
                
                // Filter out invalid objects (matches IDA's _drop_invalid_objects)
                int originalCount = revision.getObjects().size();
                List<ModelObject> validObjects = dropInvalidObjects(revision.getObjects());
                
                Msg.info(this, "Zenyard: Revision " + currentRevision + " - " + originalCount 
                    + " objects queued, " + validObjects.size() + " valid after validation");
                
                if (validObjects.isEmpty()) {
                    // Still update revision number to maintain sequence
                    setCurrentRevision(currentRevision);
                    continue;
                }
                
                // Upload objects in chunks
                List<List<ModelObject>> chunks = splitIntoChunks(validObjects);
                
                for (int i = 0; i < chunks.size(); i++) {
                    if (monitor.isCancelled()) {
                        return;
                    }
                    
                    // Calculate progress within current revision (fine-grained progress)
                    int chunkProgress = uploadProgress;
                    if (chunks.size() > 1) {
                        // Add fine-grained progress within revision (up to next revision's start)
                        int nextRevisionProgress = (totalRevisions > 0 && revIndex + 1 < totalRevisions) 
                            ? (int)(((revIndex + 1) / (double)totalRevisions) * 100) 
                            : 100;
                        int revisionRange = nextRevisionProgress - uploadProgress;
                        chunkProgress = uploadProgress + (int)((i / (double)chunks.size()) * revisionRange);
                    }
                    String chunkMessage = "Uploading chunk " + (i + 1) + "/" + chunks.size() 
                        + " of revision " + currentRevision + " (" + chunkProgress + "%)";
                    if (statusBarManager != null) {
                        statusBarManager.updateTaskStatus(TASK_ID, chunkMessage, chunkProgress, false);
                    }
                    
                    List<ModelObject> chunk = chunks.get(i);
                    Msg.info(this, "Zenyard: Uploading chunk " + (i + 1) + "/" + chunks.size() 
                        + " with " + chunk.size() + " objects to revision " + currentRevision);
                    
                    AddObjectsToCurrentRevisionParams addParams = new AddObjectsToCurrentRevisionParams();
                    addParams.setObjects(chunk);
                    
                    try {
                        CompletableFuture.supplyAsync(() -> {
                            try {
                                binariesApi.addObjectsToCurrentRevision(binaryId, addParams);
                                return null;
                            } catch (ApiException e) {
                                throw new RuntimeException(e);
                            }
                        }).get();
                        Msg.info(this, "Zenyard: Successfully uploaded chunk " + (i + 1) + " with " + chunk.size() + " objects");
                    } catch (Exception e) {
                        Msg.showError(this, tool.getActiveWindow(), "Upload Error",
                            "Failed to upload chunk " + (i + 1) + " of revision " + currentRevision 
                            + ": " + e.getMessage(), e);
                        throw new RuntimeException("Failed to upload chunk " + (i + 1), e);
                    }
                }
                
                // Finish revision (mirrors IDA: analyze_dependents = !is_initial_analysis)
                boolean analyzeDependents = !revision.isInitialAnalysis();
                boolean performGlobalAnalysis = revision.isPerformGlobalAnalysis();
                FinishAndAnalyzeCurrentRevisionBody finishParams = new FinishAndAnalyzeCurrentRevisionBody();
                finishParams.setAnalyzeDependents(analyzeDependents);
                finishParams.setSwiftOnly(false);
                finishParams.setPerformGlobalAnalysis(performGlobalAnalysis);
                
                // Evidence log: only last revision should set performGlobalAnalysis=true.
                if (performGlobalAnalysis) {
                    Msg.info(this, "Zenyard: Finishing revision " + currentRevision
                        + " with performGlobalAnalysis=true ("
                        + (revIndex + 1) + "/" + totalRevisions
                        + ", analyzeDependents=" + analyzeDependents
                        + ", swiftOnly=false)");
                }

                finishAndAnalyzeWithRetry(binaryId, finishParams, currentRevision, analyzeDependents, performGlobalAnalysis);

                // Clear dirty list for objects in this revision after successful upload
                markUploadedObjects(revision, syncStatusStorage);
                
                // Update revision number
                setCurrentRevision(currentRevision);
            }
            
            // Mark database as clean after successful upload
            ZenyardProgramProperties uploadProps = new ZenyardProgramProperties(program);
            uploadProps.setString("database_dirty", "false");
            clearRerunStateAfterSync();
            
            // Mark initial upload as complete if this was the initial upload
            if (isInitialUpload) {
                props.setString("initial_upload_complete", "true");
            }
            
            // Publish completion events
            publishEvent(new ZenyardEvent(ZenyardEvent.EventType.REVISIONS_UPLOADED, getTaskTitle()));
            if (isInitialUpload) {
                publishEvent(new ZenyardEvent(ZenyardEvent.EventType.INITIAL_UPLOAD_COMPLETE, getTaskTitle()));
            }
            
            if (statusBarManager != null) {
                statusBarManager.updateTaskStatus(TASK_ID, "Upload complete", 100, false);
            }
            });
            } catch (Exception e) {
                Msg.showError(this, tool.getActiveWindow(), "Upload Error",
                    "Failed to upload revisions: " + e.getMessage(), e);
                throw new RuntimeException("Failed to upload revisions", e);
            }
        } finally {
            runningFlag.set(false);
            RUNNING_UPLOADS.remove(program, runningFlag);
            runningMonitor = null;
        }
    }

    private void finishAndAnalyzeWithRetry(
            UUID binaryId,
            FinishAndAnalyzeCurrentRevisionBody finishParams,
            int currentRevision,
            boolean analyzeDependents,
            boolean performGlobalAnalysis) {
        int attempt = 0;
        int maxAttempts = 3;
        while (true) {
            attempt++;
            try {
                binariesApi.finishAndAnalyzeCurrentRevision(binaryId, finishParams);
                if (performGlobalAnalysis) {
                    Msg.info(this, "Zenyard: Finish-and-analyze succeeded for revision " + currentRevision
                        + " (performGlobalAnalysis=true, analyzeDependents=" + analyzeDependents
                        + ", swiftOnly=false)");
                }
                return;
            } catch (ApiException e) {
                String responseBody = e.getResponseBody();
                Msg.warn(this, "Finish and analyze failed for revision " + currentRevision
                    + " (attempt " + attempt + "/" + maxAttempts
                    + ", code=" + e.getCode()
                    + ", performGlobalAnalysis=" + performGlobalAnalysis
                    + ", analyzeDependents=" + analyzeDependents
                    + ", swiftOnly=false): "
                    + (responseBody != null ? responseBody : e.getMessage()));
                if (responseBody != null && responseBody.contains("No current edited revision")) {
                    throw new RuntimeException(e);
                }
                if (attempt >= maxAttempts || e.getCode() < 500) {
                    throw new RuntimeException(e);
                }
            } catch (Exception e) {
                if (attempt >= maxAttempts) {
                    throw new RuntimeException(e);
                }
                Msg.warn(this, "Finish and analyze error for revision " + currentRevision
                    + " (attempt " + attempt + "/" + maxAttempts
                    + ", performGlobalAnalysis=" + performGlobalAnalysis
                    + ", analyzeDependents=" + analyzeDependents
                    + ", swiftOnly=false): " + e.getMessage());
            }

            try {
                Thread.sleep(500L * attempt);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted during finish-and-analyze retry", ie);
            }
        }
    }

    private void markUploadedObjects(QueueRevisionsTask.Revision revision, SyncStatusStorage syncStatusStorage) {
        if (revision == null || syncStatusStorage == null) {
            return;
        }
        List<QueueRevisionsTask.QueuedObject> queuedObjects = revision.getQueuedObjects();
        if (queuedObjects == null || queuedObjects.isEmpty()) {
            return;
        }
        for (QueueRevisionsTask.QueuedObject queued : queuedObjects) {
            if (queued == null || queued.getAddress() == null) {
                continue;
            }
            SyncStatus newStatus = new SyncStatus(Optional.ofNullable(queued.getHash()), false);
            syncStatusStorage.setSyncStatus(queued.getAddress(), newStatus);
        }
    }

    private void clearRerunStateAfterSync() {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        props.setString("changes_detected", "false");

        StatusBarManager statusBarManager = getStatusBarManager();
        if (statusBarManager == null) {
            return;
        }
        StatusBarViewModel viewModel = statusBarManager.getViewModel();
        if (viewModel != null) {
            StatusBarState current = viewModel.getStateSnapshot();
            viewModel.updateState(current.withShowRerun(false));
        }
        statusBarManager.refreshDisplayNow();
    }

    /**
     * Split objects into chunks respecting max upload size.
     */
    private List<List<ModelObject>> splitIntoChunks(List<ModelObject> objects) {
        List<List<ModelObject>> chunks = new ArrayList<>();
        List<ModelObject> currentChunk = new ArrayList<>();
        int currentChunkBytes = 0;
        
        // Simple JSON size estimation (rough)
        for (ModelObject obj : objects) {
            // Estimate size (rough - actual size would require serialization)
            int estimatedSize = estimateObjectSize(obj);
            
            if (!currentChunk.isEmpty() 
                && currentChunkBytes + estimatedSize > MAX_UPLOAD_BYTES) {
                chunks.add(new ArrayList<>(currentChunk));
                currentChunk.clear();
                currentChunkBytes = 0;
            }
            
            currentChunk.add(obj);
            currentChunkBytes += estimatedSize;
        }
        
        if (!currentChunk.isEmpty()) {
            chunks.add(currentChunk);
        }
        
        return chunks;
    }
    
    /**
     * Estimate object size in bytes (rough estimate).
     */
    private int estimateObjectSize(ModelObject obj) {
        // Rough estimate: 1KB per object
        // In a real implementation, we'd serialize to JSON to get actual size
        return 1024;
    }
    
    /**
     * Get current revision number.
     */
    private int getCurrentRevision() {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        Integer revision = props.getInt("revision");
        if (revision != null) {
            return revision;
        }
        return 1;
    }
    
    /**
     * Set current revision number.
     */
    private void setCurrentRevision(int revision) {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        props.setInt("revision", revision);
    }
    
    /**
     * Filter out invalid objects before uploading.
     * Matches IDA's _drop_invalid_objects() logic.
     * 
     * @param objects List of objects to validate
     * @return List of valid objects
     */
    private List<ModelObject> dropInvalidObjects(List<ModelObject> objects) {
        List<ModelObject> validObjects = new ArrayList<>();
        int droppedCount = 0;
        for (ModelObject obj : objects) {
            if (isValidObject(obj)) {
                validObjects.add(obj);
            } else {
                droppedCount++;
                String address = getObjectAddress(obj);
                Msg.debug(this, "Zenyard: Dropping invalid object at address: " + address);
            }
        }
        if (droppedCount > 0) {
            Msg.warn(this, "Zenyard: Dropped " + droppedCount + " invalid objects out of " + objects.size() + " total");
        }
        Msg.info(this, "Zenyard: Validated " + objects.size() + " objects, " + validObjects.size() + " valid, " + droppedCount + " dropped");
        return validObjects;
    }
    
    /**
     * Check if an object is valid for upload.
     * 
     * @param obj The object to validate
     * @return true if valid, false otherwise
     */
    private boolean isValidObject(ModelObject obj) {
        try {
            if (obj == null) {
                Msg.debug(this, "Zenyard: Object is null");
                return false;
            }
            Object actualInstance = obj.getActualInstance();
            if (actualInstance == null) {
                Msg.debug(this, "Zenyard: Object actualInstance is null");
                return false;
            }
            
            // Check if it's a Function object (using string comparison to avoid class loading issues)
            String className = actualInstance.getClass().getName();
            Msg.debug(this, "Zenyard: Validating object of type: " + className);
            
            // Check for Function objects
            if (className.contains("Function")) {
                if (actualInstance instanceof Function) {
                    return validateFunction((Function) actualInstance);
                }
            } else if (className.contains("GlobalVariable")) {
                if (actualInstance instanceof GlobalVariable) {
                    return validateGlobalVariable((GlobalVariable) actualInstance);
                }
            } else if (className.contains("Section")) {
                if (actualInstance instanceof Section) {
                    return validateSection((Section) actualInstance);
                }
            }
            
            // Unknown object type - reject for safety
            Msg.debug(this, "Zenyard: Unknown object type, rejecting: " + className);
            return false;
        } catch (Exception e) {
            // If validation fails for any reason, reject the object
            Msg.debug(this, "Zenyard: Object validation exception: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Validate global variable object before uploading.
     */
    private boolean validateGlobalVariable(GlobalVariable gv) {
        if (gv == null) {
            return false;
        }
        return !gv.getAddress().isEmpty() && !gv.getName().isEmpty();
    }
    
    /**
     * Validate section object before uploading.
     */
    private boolean validateSection(Section section) {
        if (section == null) {
            return false;
        }
        return section.getAddress() != null && !section.getAddress().isEmpty()
            && section.getName() != null && !section.getName().isEmpty();
    }
    
    /**
     * Validate function object before uploading.
     * Matches IDA's validate_object() logic from zenyard_ida/objects.py.
     * 
     * @param func The function to validate
     * @return true if valid, false otherwise
     */
    private boolean validateFunction(Function func) {
        if (func == null) {
            return false;
        }
        if (func.getAddress().isEmpty()) {
            return false;
        }
        if (func.getCode().isEmpty()) {
            return false;
        }
        List<Range> ranges = func.getRanges();
        if (ranges == null || ranges.isEmpty()) {
            return true;
        }
        String code = func.getCode();
        List<Range> sortedRanges = new ArrayList<>(ranges);
        sortedRanges.sort((r1, r2) -> Integer.compare(
            r1.getStart() != null ? r1.getStart() : -1,
            r2.getStart() != null ? r2.getStart() : -1
        ));
        int lastEnd = -1;
        for (Range range : sortedRanges) {
            Integer start = range.getStart();
            Integer length = range.getLength();
            if (start == null || length == null) {
                return false;
            }
            if (start < 0 || length < 0) {
                return false;
            }
            int end = start + length;
            if (end > code.length()) {
                return false;
            }
            if (start < lastEnd) {
                return false;
            }
            lastEnd = end;
        }
        return true;
    }
    
    /**
     * Get address string from an object for logging purposes.
     * 
     * @param obj The object
     * @return Address string or "unknown"
     */
    private String getObjectAddress(ModelObject obj) {
        try {
            Object actualInstance = obj.getActualInstance();
            if (actualInstance instanceof Function) {
                Function func = (Function) actualInstance;
                String address = func.getAddress();
                return address != null ? address : "unknown";
            } else if (actualInstance instanceof GlobalVariable) {
                GlobalVariable gv = (GlobalVariable) actualInstance;
                String address = gv.getAddress();
                return address != null ? address : "unknown";
            } else if (actualInstance instanceof Section) {
                Section section = (Section) actualInstance;
                String address = section.getAddress();
                return address != null ? address : "unknown";
            }
            return "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }
}
