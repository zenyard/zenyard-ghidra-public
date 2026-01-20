package com.zenyard.decompai.ghidra.upload;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import com.zenyard.decompai.ghidra.api.generated.api.BinariesApi;
import com.zenyard.decompai.ghidra.api.generated.model.AddObjectsToCurrentRevisionParams;
import com.zenyard.decompai.ghidra.api.generated.model.CreateRevisionParams;
import com.zenyard.decompai.ghidra.api.generated.model.FinishAndAnalyzeCurrentRevisionParams;
import com.zenyard.decompai.ghidra.api.generated.model.Function;
import com.zenyard.decompai.ghidra.api.generated.model.GlobalVariable;
import com.zenyard.decompai.ghidra.api.generated.model.LineRange;
import com.zenyard.decompai.ghidra.api.generated.model.ModelObject;
import com.zenyard.decompai.ghidra.api.generated.model.Range;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.events.EventConsumer;
import com.zenyard.decompai.ghidra.events.EventDispatcher;
import com.zenyard.decompai.ghidra.events.EventProducer;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;
import com.zenyard.decompai.ghidra.status.StatusBarManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Background task to upload revisions with status bar progress.
 * Waits for REVISIONS_QUEUED event, then uploads revisions.
 * Publishes REVISIONS_UPLOADED or INITIAL_UPLOAD_COMPLETE events.
 * 
 * NOTE: mirrors decompai_ida/upload_revisions_task.py
 */
public class UploadRevisionsTask extends Task implements EventConsumer, EventProducer {
    
    private static final int MAX_UPLOAD_BYTES = 10 * 1024 * 1024; // 10MB
    private static final String TASK_ID = "upload_revisions";
    private static final int STATUS_BAR_PRIORITY = com.zenyard.decompai.ghidra.status.StatusBarPriorities.UPLOAD_REVISIONS;
    
    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final StatusBarManager statusBarManager;
    private final Program program;
    private final EventDispatcher eventDispatcher;
    
    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean revisionsQueued = false;
    private volatile boolean shouldStop = false;
    private List<QueueRevisionsTask.Revision> revisions = new ArrayList<>();
    private UUID binaryId = null;
    private boolean isInitialUpload = false;
    private volatile boolean binaryIdAvailable = false;
    
    public UploadRevisionsTask(PluginTool tool, BinariesApi binariesApi,
                               StatusBarManager statusBarManager, Program program, EventDispatcher eventDispatcher) {
        super("Upload Revisions", true, false, false); // canCancel=true, hasProgress=false, isModal=false
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.statusBarManager = statusBarManager;
        this.program = program;
        this.eventDispatcher = eventDispatcher;
    }
    
    @Override
    public Set<DecompaiEvent.EventType> getSubscribedEventTypes() {
        Set<DecompaiEvent.EventType> types = new HashSet<>();
        types.add(DecompaiEvent.EventType.REVISIONS_QUEUED);
        types.add(DecompaiEvent.EventType.BINARY_ID_AVAILABLE);
        types.add(DecompaiEvent.EventType.PROGRAM_DEACTIVATED);
        return types;
    }
    
    @Override
    public void handleEvent(DecompaiEvent event) {
        if (event.getType() == DecompaiEvent.EventType.REVISIONS_QUEUED) {
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
                DecompaiProgramProperties props = new DecompaiProgramProperties(program);
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
        } else if (event.getType() == DecompaiEvent.EventType.BINARY_ID_AVAILABLE) {
            UUID eventBinaryId = event.getPayloadValue("binaryId", UUID.class);
            if (eventBinaryId != null) {
                synchronized (waitLock) {
                    this.binaryId = eventBinaryId;
                    this.binaryIdAvailable = true;
                    waitLock.notify();
                }
            }
        } else if (event.getType() == DecompaiEvent.EventType.PROGRAM_DEACTIVATED) {
            Msg.info(this, "UploadRevisionsTask: Received PROGRAM_DEACTIVATED event");
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
    
    @Override
    public void run(TaskMonitor monitor) {
        // Subscribe to events
        if (eventDispatcher != null) {
            eventDispatcher.subscribe(this);
        }
        
        try {
            // Get binary ID from properties
            DecompaiProgramProperties props = new DecompaiProgramProperties(program);
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
            
            Msg.info(this, "UploadRevisionsTask: Exited wait loop, revisionsQueued=" + revisionsQueued + 
                ", revisions.size()=" + revisions.size() + ", shouldStop=" + shouldStop);
            
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
                return;
            }
            
            if (monitor.isCancelled() || shouldStop) {
                Msg.info(this, "UploadRevisionsTask: Cancelled or stopped, aborting upload");
                return;
            }
            
            Msg.info(this, "UploadRevisionsTask: Starting upload of " + revisions.size() + " revision(s) for binaryId: " + binaryId);
            
            // Register with status bar
            if (statusBarManager != null) {
                statusBarManager.registerTask(TASK_ID, STATUS_BAR_PRIORITY);
            }
            
            int currentRevision = getCurrentRevision();
            int totalRevisions = revisions.size();
            int startRevision = currentRevision;
            
            for (int revIndex = 0; revIndex < revisions.size(); revIndex++) {
                if (monitor.isCancelled() || shouldStop) {
                    if (statusBarManager != null) {
                        statusBarManager.unregisterTask(TASK_ID);
                    }
                    return;
                }
                
                QueueRevisionsTask.Revision revision = revisions.get(revIndex);
                currentRevision++;
                
                // Calculate progress percentage
                int uploadProgress = 0;
                if (totalRevisions > 0) {
                    uploadProgress = (int)((revIndex / (double)totalRevisions) * 100);
                }
                String uploadMessage = "Uploading revision " + currentRevision + "/" + 
                    (startRevision + totalRevisions) + " (" + uploadProgress + "%)";
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
                    } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                        throw new RuntimeException(e);
                    }
                }).get();
                
                // Filter out invalid objects (matches IDA's _drop_invalid_objects)
                int originalCount = revision.getObjects().size();
                List<ModelObject> validObjects = dropInvalidObjects(revision.getObjects());
                
                Msg.info(this, "DecompAI: Revision " + currentRevision + " - " + originalCount + 
                    " objects queued, " + validObjects.size() + " valid after validation");
                
                if (validObjects.isEmpty()) {
                    // Still update revision number to maintain sequence
                    setCurrentRevision(currentRevision);
                    continue;
                }
                
                // Upload objects in chunks
                List<List<ModelObject>> chunks = splitIntoChunks(validObjects);
                
                for (int i = 0; i < chunks.size(); i++) {
                    if (monitor.isCancelled()) {
                        if (statusBarManager != null) {
                            statusBarManager.unregisterTask(TASK_ID);
                        }
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
                    String chunkMessage = "Uploading chunk " + (i + 1) + "/" + chunks.size() + 
                        " of revision " + currentRevision + " (" + chunkProgress + "%)";
                    if (statusBarManager != null) {
                        statusBarManager.updateTaskStatus(TASK_ID, chunkMessage, chunkProgress, false);
                    }
                    
                    List<ModelObject> chunk = chunks.get(i);
                    Msg.info(this, "DecompAI: Uploading chunk " + (i + 1) + "/" + chunks.size() + 
                        " with " + chunk.size() + " objects to revision " + currentRevision);
                    
                    AddObjectsToCurrentRevisionParams addParams = new AddObjectsToCurrentRevisionParams();
                    addParams.setObjects(chunk);
                    
                    try {
                        CompletableFuture.supplyAsync(() -> {
                            try {
                                binariesApi.addObjectsToCurrentRevision(binaryId, addParams);
                                return null;
                            } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                                throw new RuntimeException(e);
                            }
                        }).get();
                        Msg.info(this, "DecompAI: Successfully uploaded chunk " + (i + 1) + " with " + chunk.size() + " objects");
                    } catch (Exception e) {
                        Msg.showError(this, tool.getActiveWindow(), "Upload Error",
                            "Failed to upload chunk " + (i + 1) + " of revision " + currentRevision + 
                            ": " + e.getMessage(), e);
                        if (statusBarManager != null) {
                            statusBarManager.unregisterTask(TASK_ID);
                        }
                        throw new RuntimeException("Failed to upload chunk " + (i + 1), e);
                    }
                }
                
                // Finish revision
                boolean analyzeDependents = revision.isInitialAnalysis();
                FinishAndAnalyzeCurrentRevisionParams finishParams = new FinishAndAnalyzeCurrentRevisionParams();
                finishParams.setAnalyzeDependents(analyzeDependents);
                
                CompletableFuture.supplyAsync(() -> {
                    try {
                        binariesApi.finishAndAnalyzeCurrentRevision(binaryId, finishParams);
                        return null;
                    } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                        throw new RuntimeException(e);
                    }
                }).get();
                
                // Update revision number
                setCurrentRevision(currentRevision);
            }
            
            // Mark database as clean after successful upload
            DecompaiProgramProperties uploadProps = new DecompaiProgramProperties(program);
            uploadProps.setString("database_dirty", "false");
            
            // Mark initial upload as complete if this was the initial upload
            if (isInitialUpload) {
                props.setString("initial_upload_complete", "true");
            }
            
            // Publish completion events
            publishEvent(new DecompaiEvent(DecompaiEvent.EventType.REVISIONS_UPLOADED, getTaskTitle()));
            if (isInitialUpload) {
                publishEvent(new DecompaiEvent(DecompaiEvent.EventType.INITIAL_UPLOAD_COMPLETE, getTaskTitle()));
            }
            
            if (statusBarManager != null) {
                statusBarManager.updateTaskStatus(TASK_ID, "Upload complete", 100, false);
                statusBarManager.unregisterTask(TASK_ID);
            }
            
        } catch (Exception e) {
            Msg.showError(this, tool.getActiveWindow(), "Upload Error",
                "Failed to upload revisions: " + e.getMessage(), e);
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(TASK_ID);
            }
            throw new RuntimeException("Failed to upload revisions", e);
        } finally {
            // Unsubscribe from events
            if (eventDispatcher != null) {
                eventDispatcher.unsubscribe(this);
            }
        }
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
            
            if (!currentChunk.isEmpty() && 
                currentChunkBytes + estimatedSize > MAX_UPLOAD_BYTES) {
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
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
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
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
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
                Msg.debug(this, "DecompAI: Dropping invalid object at address: " + address);
            }
        }
        if (droppedCount > 0) {
            Msg.warn(this, "DecompAI: Dropped " + droppedCount + " invalid objects out of " + objects.size() + " total");
        }
        Msg.info(this, "DecompAI: Validated " + objects.size() + " objects, " + validObjects.size() + " valid, " + droppedCount + " dropped");
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
                Msg.debug(this, "DecompAI: Object is null");
                return false;
            }
            Object actualInstance = obj.getActualInstance();
            if (actualInstance == null) {
                Msg.debug(this, "DecompAI: Object actualInstance is null");
                return false;
            }
            
            // Check if it's a Function object (using string comparison to avoid class loading issues)
            String className = actualInstance.getClass().getName();
            Msg.debug(this, "DecompAI: Validating object of type: " + className);
            
            // Check for Function objects
            if (className.contains("Function")) {
                if (actualInstance instanceof Function) {
                    return validateFunction((Function) actualInstance);
                }
            } else if (className.contains("GlobalVariable")) {
                if (actualInstance instanceof GlobalVariable) {
                    return validateGlobalVariable((GlobalVariable) actualInstance);
                }
            }
            
            // Unknown object type - reject for safety
            Msg.debug(this, "DecompAI: Unknown object type, rejecting: " + className);
            return false;
        } catch (Exception e) {
            // If validation fails for any reason, reject the object
            Msg.debug(this, "DecompAI: Object validation exception: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Validate global variable object before uploading.
     */
    private boolean validateGlobalVariable(GlobalVariable gv) {
        try {
            // GlobalVariable requires address and name (both non-null per API)
            if (gv.getAddress() == null || gv.getAddress().isEmpty()) {
                return false;
            }
            
            if (gv.getName() == null || gv.getName().isEmpty()) {
                return false;
            }
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Validate function object before uploading.
     * Matches IDA's validate_object() logic from decompai_ida/objects.py.
     * 
     * @param func The function to validate
     * @return true if valid, false otherwise
     */
    private boolean validateFunction(Function func) {
        try {
            // Address is required
            if (func.getAddress() == null || func.getAddress().isEmpty()) {
                return false;
            }
            
            // Code is required
            if (func.getCode() == null || func.getCode().isEmpty()) {
                return false;
            }
            
            String code = func.getCode();
            
            // Validate ranges if present
            List<Range> ranges = func.getRanges();
            if (ranges != null && !ranges.isEmpty()) {
                // Validate ranges are within code bounds
                for (Range range : ranges) {
                    if (range.getStart() == null || range.getLength() == null) {
                        return false; // Range has null values
                    }
                    if (range.getStart() < 0 || range.getStart() + range.getLength() > code.length()) {
                        return false; // Range out of code bounds
                    }
                }
                
                // Validate ranges do not overlap
                List<Range> sortedRanges = new ArrayList<>(ranges);
                sortedRanges.sort((r1, r2) -> Integer.compare(
                    r1.getStart() != null ? r1.getStart() : 0,
                    r2.getStart() != null ? r2.getStart() : 0
                ));
                
                for (int i = 0; i < sortedRanges.size() - 1; i++) {
                    Range r1 = sortedRanges.get(i);
                    Range r2 = sortedRanges.get(i + 1);
                    if (r1.getStart() != null && r1.getLength() != null && 
                        r2.getStart() != null && 
                        r2.getStart() < r1.getStart() + r1.getLength()) {
                        return false; // Overlapping ranges
                    }
                }
            }
            
            // If present, line ranges must cover the entire function
            // Note: This validation matches IDA's validate_object() but may be optional
            // Skip for now if getLineRanges() is not available in generated model
            try {
                List<LineRange> lineRanges = func.getLineRanges();
                if (lineRanges != null && !lineRanges.isEmpty()) {
                    int coveredLines = 0;
                    for (LineRange lineRange : lineRanges) {
                        if (lineRange.getLineCount() != null) {
                            coveredLines += lineRange.getLineCount();
                        }
                    }
                    // Count lines in code (remove trailing newlines first)
                    String codeWithoutTrailingNewlines = code.replaceAll("\n+$", "");
                    int codeLines = codeWithoutTrailingNewlines.isEmpty() ? 0 : 
                        codeWithoutTrailingNewlines.split("\n").length;
                    if (codeLines == 0 && !code.isEmpty()) {
                        codeLines = 1; // Single line of code
                    }
                    if (coveredLines != codeLines) {
                        return false; // Line ranges don't cover entire function
                    }
                }
            } catch (Exception e) {
                // If line ranges validation fails, don't reject the function
                // This allows functions without line ranges to pass validation
            }
            
            return true;
        } catch (Exception e) {
            return false;
        }
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
            }
            return "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }
}
