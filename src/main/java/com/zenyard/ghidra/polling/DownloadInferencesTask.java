package com.zenyard.ghidra.polling;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;

import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.model.GetInferencesResponse;
import com.zenyard.ghidra.api.generated.model.Inference;
import com.zenyard.ghidra.api.generated.model.MaybeUnknownInference;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.tasks.StatusBarAwareTask;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.status.StatusBarManager;
import com.zenyard.ghidra.status.StatusBarPriorities;
import com.zenyard.ghidra.util.ZenyardConstants;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Background task that polls for new inferences every 1 second.
 * Registers with status bar when downloading.
 * Waits for BINARY_ID_AVAILABLE event before starting.
 * Publishes NEW_INFERENCES_AVAILABLE events when inferences are downloaded.
 * 
 * NOTE: mirrors zenyard_ida/download_inferences_task.py
 */
public class DownloadInferencesTask extends StatusBarAwareTask {
    
    private static final int POLL_INTERVAL_MS = ZenyardConstants.POLL_INTERVAL_MS;
    private static final int MAX_INFERENCES_PER_REQUEST = 50;
    private static final int MAX_BACKOFF_MS = ZenyardConstants.MAX_BACKOFF_MS;
    private static final int INITIAL_BACKOFF_MS = ZenyardConstants.INITIAL_BACKOFF_MS;
    private static final double REVISION_EPS = 1e-6;
    private static final String TASK_ID = "download_inferences";
    private static final String LATEST_RESULTS_TASK_ID = "latest_results_applied";
    private static final int STATUS_BAR_PRIORITY = StatusBarPriorities.DOWNLOAD_INFERENCES;
    
    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final InferenceQueue inferenceQueue;
    private final StatusBarManager statusBarManager;
    private final Program program;
    private volatile boolean shouldStop = false;
    private int consecutiveConnectionFailures = 0;
    private boolean lastConnected = true;

    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean binaryIdAvailable = false;
    private UUID binaryId = null;
    
    public DownloadInferencesTask(PluginTool tool, BinariesApi binariesApi,
                                  InferenceQueue inferenceQueue, StatusBarManager statusBarManager,
                                  Program program, EventDispatcher eventDispatcher) {
        super("Download Inferences", true, false, false, eventDispatcher, statusBarManager, TASK_ID, STATUS_BAR_PRIORITY);
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.inferenceQueue = inferenceQueue;
        this.statusBarManager = statusBarManager;
        this.program = program;
    }
    
    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        Set<ZenyardEvent.EventType> types = new HashSet<>();
        types.add(ZenyardEvent.EventType.BINARY_ID_AVAILABLE);
        types.add(ZenyardEvent.EventType.PROGRAM_DEACTIVATED);
        types.add(ZenyardEvent.EventType.SERVER_REVISION_UPDATED);
        return types;
    }
    
    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.BINARY_ID_AVAILABLE) {
            // Extract binary ID from event payload or get from properties
            UUID eventBinaryId = event.getPayloadValue("binaryId", UUID.class);
            if (eventBinaryId != null) {
                synchronized (waitLock) {
                    this.binaryId = eventBinaryId;
                    this.binaryIdAvailable = true;
                    waitLock.notify();
                }
            } else {
                // Fallback: get from properties
                ZenyardProgramProperties props = new ZenyardProgramProperties(program);
                String binaryIdStr = props.getString("binary_id");
                if (binaryIdStr != null && !binaryIdStr.isEmpty()) {
                    try {
                        synchronized (waitLock) {
                            this.binaryId = UUID.fromString(binaryIdStr);
                            this.binaryIdAvailable = true;
                            waitLock.notify();
                        }
                    } catch (IllegalArgumentException e) {
                        // Invalid UUID format
                    }
                }
            }
        } else if (event.getType() == ZenyardEvent.EventType.PROGRAM_DEACTIVATED) {
            synchronized (waitLock) {
                shouldStop = true;
                waitLock.notify(); // Wake up any waiting threads
            }
        } else if (event.getType() == ZenyardEvent.EventType.SERVER_REVISION_UPDATED) {
            // Server revision was updated - wake up waiting thread in fetchInferences()
            synchronized (waitLock) {
                waitLock.notify();
            }
        }
    }
    
    @Override
    protected void doRun(TaskMonitor monitor) {
        try {
            // Wait for BINARY_ID_AVAILABLE event
            synchronized (waitLock) {
                while (!binaryIdAvailable && !shouldStop && !monitor.isCancelled()) {
                    // Check if binary ID is already available
                    ZenyardProgramProperties props = new ZenyardProgramProperties(program);
                    String binaryIdStr = props.getString("binary_id");
                    if (binaryIdStr != null && !binaryIdStr.isEmpty()) {
                        try {
                            this.binaryId = UUID.fromString(binaryIdStr);
                            this.binaryIdAvailable = true;
                            break;
                        } catch (IllegalArgumentException e) {
                            // Invalid UUID format, continue waiting
                        }
                    }
                    
                    try {
                        waitLock.wait(1000); // Wait up to 1 second, then check again
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
            
            if (binaryId == null || shouldStop || monitor.isCancelled()) {
                return; // No binary ID, stop polling
            }
            
            // Main loop: fetch inferences for current revision, then wait for new revision
            while (!shouldStop && !monitor.isCancelled()) {
                try {
                    // Fetch all inferences for current revision
                    fetchInferences(monitor, binaryId);
                    
                    // Wait for new revision to be available
                    waitForNewRevision(monitor);

                } catch (Exception e) {
                    // Handle connection errors with exponential backoff
                    if (ConnectionErrorHandler.isConnectionError(e)) {
                        Throwable rootCause = ConnectionErrorHandler.findRootCause(e);
                        int updatedFailures = consecutiveConnectionFailures + 1;
                        int backoffMs = ConnectionErrorHandler.calculateBackoff(
                            updatedFailures, INITIAL_BACKOFF_MS, MAX_BACKOFF_MS);
                        
                        Msg.warn(this, "Connection error downloading inferences: " + rootCause.getMessage() 
                            + " (attempt " + updatedFailures + ", backoff " + backoffMs + "ms)");
                        updateConnectivity(false);
                        
                        try {
                            Thread.sleep(backoffMs);
                            consecutiveConnectionFailures = updatedFailures;
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                    } else {
                        // Other error - reset connection failure counter and use normal interval
                        consecutiveConnectionFailures = 0;
                        Msg.warn(this, "Error downloading inferences: " + e.getMessage());
                        // Continue polling despite errors
                        try {
                            Thread.sleep(POLL_INTERVAL_MS);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.showError(this, tool.getActiveWindow(), "Download Error",
                "Failed to download inferences: " + e.getMessage(), e);
        }
    }
    
    /**
     * Stop the download task.
     */
    public void stop() {
        shouldStop = true;
    }
    
    /**
     * Fetch all inferences for current revision.
     * Returns when done fetching (has_next == false AND server_revision == current_revision).
     * Matches IDA's _fetch_inferences() logic.
     */
    private void fetchInferences(TaskMonitor monitor, UUID binaryId) {
        // Clear "Latest results applied" message when starting new download
        if (statusBarManager != null) {
            statusBarManager.unregisterTask(LATEST_RESULTS_TASK_ID);
        }

        try {
            runWithStatusBar(() -> {
                int currentRevision = getCurrentRevision();
                int cursor = getInferenceCursor();

                // Register with status bar when starting to fetch (like IDA's report_and_notify_background_task)
                if (statusBarManager != null) {
                    statusBarManager.updateTaskStatus(TASK_ID, "Downloading results", null, true);
                }

                while (!shouldStop && !monitor.isCancelled()) {
                    double serverRevision = getServerRevisionFractional();
                    // Local revision may have progressed while downloading
                    currentRevision = getCurrentRevision();
                
                // Fetch a page of inferences
                GetInferencesResponse response = fetchInferencePage(binaryId, currentRevision, cursor);
                if (response == null) {
                    // Error fetching page - wait before retrying
                    try {
                        Thread.sleep(POLL_INTERVAL_MS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    continue;
                }
                
                // Process inferences from response
                boolean inferencesAdded = false;
                if (response.getInferences() != null) {
                    for (MaybeUnknownInference inference : response.getInferences()) {
                        if (inference == null) {
                            continue;
                        }
                        if (inference.getInference() == null) {
                            Msg.debug(this, "DownloadInferencesTask: inference slot had no typed "
                                + "payload (discarded — often unknown OpenAPI discriminator)");
                            continue;
                        }
                        inferenceQueue.enqueue(inference.getInference());
                        inferencesAdded = true;
                    }
                }
                
                // Publish event when new inferences are added
                if (inferencesAdded) {
                    int inferenceCount = response.getInferences() != null ? response.getInferences().size() : 0;
                    Msg.debug(this, "DownloadInferencesTask: Publishing NEW_INFERENCES_AVAILABLE event for "
                        + inferenceCount + " new inferences");
                    publishEvent(new ZenyardEvent(ZenyardEvent.EventType.NEW_INFERENCES_AVAILABLE, 
                        getTaskTitle()));
                }
                
                // Update status bar - keep download as an indeterminate \"busy\" task,
                // matching IDA's \"Downloading results\" behavior. We don't know the
                // total number of inferences, so we avoid showing a percentage.
                if (statusBarManager != null) {
                    statusBarManager.updateTaskStatus(TASK_ID, "Downloading results", null, true);
                }
                
                // Update cursor
                cursor = response.getCursor();
                setInferenceCursor(cursor);
                
                // Check completion condition (matches IDA logic)
                if (response.getHasNext()) {
                    // More inferences available - continue immediately
                    // cursor already updated above
                    Msg.debug(this, "More inferences available - continuing immediately");
                } else if (Math.abs(serverRevision - currentRevision) < REVISION_EPS) {
                    // Done fetching: no more inferences AND server is exactly at currentRevision.
                    // Mirrors IDA's `server_revision == current_revision` float-vs-int equality:
                    // fractional values like 1.5 (server analyzing rev 2) must NOT match rev 1.
                    Msg.info(this, "Done fetching inferences for revision " + currentRevision);
                    return;
                } else {
                    // No more inferences in this page, but server is still analyzing
                    // Wait for SERVER_REVISION_UPDATED event before checking again
                    synchronized (waitLock) {
                        try {
                            Msg.debug(this, "Waiting for SERVER_REVISION_UPDATED event before checking again");
                            waitLock.wait(POLL_INTERVAL_MS); // Timeout as fallback
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }
                    // Re-read serverRevision after waking up (may have been updated)
                    serverRevision = getServerRevisionFractional();
                    currentRevision = getCurrentRevision();
                    Msg.debug(this, "Server revision: " + serverRevision + ", current revision: " + currentRevision);

                    // Check again if we're done (exact-equality, matches IDA)
                    if (Math.abs(serverRevision - currentRevision) < REVISION_EPS) {
                        Msg.info(this, "Done fetching inferences for revision " + currentRevision);
                        return;
                    }
                }
                }
            });
        } catch (Exception e) {
            throw new RuntimeException("Failed while downloading inferences", e);
        }
    }
    
    /**
     * Fetches a single page of inferences from the server.
     * 
     * @param binaryId The binary ID
     * @param revision The revision number
     * @param cursor The inference cursor
     * @return The response containing inferences, or null if an error occurred
     */
    private GetInferencesResponse fetchInferencePage(UUID binaryId, int revision, int cursor) {
        try {
            GetInferencesResponse response = binariesApi.getInferences(revision, binaryId, cursor, MAX_INFERENCES_PER_REQUEST);
            updateConnectivity(true);
            return response;
        } catch (Exception e) {
            Msg.warn(this, "Error fetching inference page: " + e.getMessage());
            if (ConnectionErrorHandler.isConnectionError(e)) {
                updateConnectivity(false);
            }
            return null;
        }
    }
    
    /**
     * Wait for a new revision to be available.
     * Matches IDA's _wait_for_new_revision() logic.
     */
    private void waitForNewRevision(TaskMonitor monitor) {
        int currentRevision = getCurrentRevision();
        
        // Keep showing "Downloading results" while waiting (matches IDA behavior)
        // Status bar will show the task as active with busy indicator
        
        while (!shouldStop && !monitor.isCancelled()) {
            int localRevision = getCurrentRevision();
            if (localRevision > currentRevision) {
                // New revision available - reset cursor and return
                setInferenceCursor(0);
                return;
            }
            
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
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
        // Default 0 — must match UploadRevisionsTask. On a fresh binary with no
        // uploads, no revisions exist on the server, so polling for "current
        // revision" returns 0 and any equality check sees parity.
        return 0;
    }
    
    /**
     * Get fractional server revision from properties.
     * This is the source of truth - only fractional value is stored (like Python version).
     */
    private double getServerRevisionFractional() {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        String revisionStr = props.getString("server_revision_fractional");
        if (revisionStr != null && !revisionStr.isEmpty()) {
            try {
                return Double.parseDouble(revisionStr);
            } catch (NumberFormatException e) {
                // Invalid format, fall back to default
            }
        }
        return 0.0;
    }

    /**
     * Get inference cursor.
     */
    private int getInferenceCursor() {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        Integer cursor = props.getInt("inference_cursor");
        if (cursor != null) {
            return cursor;
        }
        return 0;
    }
    
    /**
     * Set inference cursor.
     */
    private void setInferenceCursor(int cursor) {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        props.setInt("inference_cursor", cursor);
    }

    private void updateConnectivity(boolean connected) {
        if (lastConnected == connected) {
            return;
        }
        lastConnected = connected;
        java.util.Map<String, Object> payload = new java.util.HashMap<>();
        payload.put("connected", connected);
        publishEvent(new ZenyardEvent(ZenyardEvent.EventType.SERVER_CONNECTIVITY_CHANGED,
            getTaskTitle(), payload));
    }
    
    /**
     * Separates known {@link Inference} instances from unknown/future variants in a
     * raw {@link MaybeUnknownInference} list. Each unrecognised entry is forwarded to
     * {@code onUnknown} so the caller can log or handle it without coupling this
     * method to Ghidra's {@code Msg} class.
     */
    static List<Inference> filterKnownInferences(
            List<MaybeUnknownInference> raw, Consumer<Object> onUnknown) {
        List<Inference> result = new ArrayList<>();
        for (MaybeUnknownInference maybeInference : raw) {
            if (maybeInference == null) {
                continue;
            }
            Object actualInstance = maybeInference.getActualInstance();
            if (!(actualInstance instanceof Inference)) {
                onUnknown.accept(actualInstance);
                continue;
            }
            result.add((Inference) actualInstance);
        }
        return result;
    }

    /**
     * Simple queue for inferences.
     */
    public static class InferenceQueue {
        private final BlockingQueue<Inference> queue = new LinkedBlockingQueue<>();
        
        public void enqueue(Inference inference) {
            queue.offer(inference);
        }
        
        public Inference dequeue() {
            return queue.poll();
        }
        
        public int size() {
            return queue.size();
        }
        
        public boolean isEmpty() {
            return queue.isEmpty();
        }
    }
}
