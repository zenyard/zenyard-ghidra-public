package com.zenyard.ghidra.polling;

import java.util.HashSet;
import java.util.Set;
import java.time.Duration;
import java.util.UUID;

import com.zenyard.ghidra.api.generated.ApiClient;
import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.api.DefaultApi;
import com.zenyard.ghidra.api.generated.ApiException;
import com.zenyard.ghidra.api.generated.model.BinaryState;
import com.zenyard.ghidra.api.generated.model.BinaryStatePaused;
import com.zenyard.ghidra.api.generated.model.BinaryStateQueued;
import com.zenyard.ghidra.api.generated.model.BinaryStatus;
import com.zenyard.ghidra.api.generated.model.RevisionAnalysisStatus;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.tasks.EventAwareTask;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.status.AnalysisStatus;
import com.zenyard.ghidra.status.RemoteAnalysisStats;
import com.zenyard.ghidra.util.ZenyardConstants;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Background task that polls server for analysis status every 3 seconds.
 * 
 * NOTE: mirrors zenyard_ida/poll_server_status_task.py
 */
public class PollServerStatusTask extends EventAwareTask {
    
    private static final int POLL_INTERVAL_MS = ZenyardConstants.STATUS_POLL_INTERVAL_MS;
    private static final int MAX_BACKOFF_MS = ZenyardConstants.MAX_BACKOFF_MS;
    private static final int INITIAL_BACKOFF_MS = ZenyardConstants.INITIAL_BACKOFF_MS;
    private static final double REVISION_EPS = 1e-6; // floating point tolerance for revision comparisons
    private static final int CONNECTIVITY_CHECK_TIMEOUT_MS = 5000;
    private static final int STATUS_REQUEST_TIMEOUT_MS = 10000;
    private static final int BINARY_ID_WAIT_CONNECTIVITY_INTERVAL_MS = 5000;
    
    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final DefaultApi defaultApi;
    private final Program program;
    private volatile boolean shouldStop = false;
    private Integer maxServerRevision = null;
    private int consecutiveConnectionFailures = 0;
    private boolean lastConnected = true;
    
    // Event-based binary ID waiting
    private final Object waitLock = new Object();
    private volatile boolean binaryIdAvailable = false;
    private UUID binaryId = null;
    
    // Queue position tracking (only published on change, never on error)
    private Integer lastPublishedQueuePosition = null;
    private boolean hasPublishedQueuePosition = false;
    
    // Paused state tracking (only published on change, never on error)
    private Boolean lastPublishedPaused = null;
    private boolean hasPublishedPaused = false;
    
    public PollServerStatusTask(PluginTool tool, ApiClient apiClient, Program program, EventDispatcher eventDispatcher) {
        super("Poll Server Status", true, false, false, eventDispatcher);
        this.tool = tool;
        if (apiClient != null) {
            ApiClient pollClient = cloneApiClient(apiClient, STATUS_REQUEST_TIMEOUT_MS);
            ApiClient healthClient = cloneApiClient(apiClient, CONNECTIVITY_CHECK_TIMEOUT_MS);
            this.binariesApi = new BinariesApi(pollClient);
            this.defaultApi = new DefaultApi(healthClient);
        } else {
            this.binariesApi = null;
            this.defaultApi = null;
        }
        this.program = program;
    }
    
    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        Set<ZenyardEvent.EventType> types = new HashSet<>();
        types.add(ZenyardEvent.EventType.PROGRAM_DEACTIVATED);
        types.add(ZenyardEvent.EventType.BINARY_ID_AVAILABLE);
        return types;
    }
    
    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.PROGRAM_DEACTIVATED) {
            shouldStop = true;
        } else if (event.getType() == ZenyardEvent.EventType.BINARY_ID_AVAILABLE) {
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
        }
    }
    
    @Override
    protected void doRun(TaskMonitor monitor) {
        try {
            // Connectivity warnings should show even before a binary is registered (or when
            // registration is blocked by the binary-size gate). Do a quick check immediately.
            verifyConnectivityOnce();
            long lastConnectivityCheckMs = System.currentTimeMillis();

            // Wait for BINARY_ID_AVAILABLE event
            synchronized (waitLock) {
                while (!binaryIdAvailable && !shouldStop && !monitor.isCancelled()) {
                    long now = System.currentTimeMillis();
                    if (now - lastConnectivityCheckMs >= BINARY_ID_WAIT_CONNECTIVITY_INTERVAL_MS) {
                        verifyConnectivityOnce();
                        lastConnectivityCheckMs = now;
                    }

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
                Msg.debug(this, "PollServerStatusTask: No binary ID available, stopping");
                return; // No binary ID, stop polling
            }
            
            Msg.debug(this, "PollServerStatusTask: Binary ID available, starting polling loop");
            
            verifyConnectivityOnce();
            
            // Restore analysis state if it was in progress when program was closed
            restoreAnalysisStateIfNeeded();
            
            int localRevision = getLocalRevision();
            double fractionalServerRevision = getServerRevisionFractional();
            
            while (!shouldStop && !monitor.isCancelled()) {
                try {
                    // Poll server status
                    BinaryStatus status = binariesApi.getDetailedStatus(binaryId);
                    
                    // Extract and publish queue position from BinaryStatus.state
                    publishQueuePositionIfChanged(status);
                    
                    // Extract and publish paused state from BinaryStatus.state
                    publishPausedStateIfChanged(status);
                    boolean paused = extractIsPaused(status);
                    
                    // Refresh local revision each poll to avoid stale progress/ETA calculations
                    int currentLocalRevision = getLocalRevision();
                    if (currentLocalRevision != localRevision) {
                        Msg.debug(this, "PollServerStatusTask: Local revision changed: " + localRevision + " -> " + currentLocalRevision);
                        localRevision = currentLocalRevision;
                    }
                    
                    // Calculate and update server revision from status
                    // Store only fractional value (like Python version) - derive integer when needed
                    double oldFractionalServerRevision = fractionalServerRevision;
                    int currentServerRevisionInt = (int) fractionalServerRevision;
                    fractionalServerRevision = calculateServerRevisionFractional(status, currentServerRevisionInt, localRevision);
                    setServerRevisionFractional(fractionalServerRevision);
                    
                    // Publish event if server revision changed (compare fractional values like Python version)
                    // This ensures events are published even when only the fractional part changes (e.g., 5.7 -> 5.8)
                    // Use tolerance-based comparison for floating point to handle precision issues
                    double tolerance = 0.0001;
                    boolean revisionChanged = Math.abs(oldFractionalServerRevision - fractionalServerRevision) > tolerance;
                    
                    if (revisionChanged) {
                        Msg.debug(this, "Server revision changed: " + oldFractionalServerRevision + " -> " + fractionalServerRevision);
                        java.util.Map<String, Object> payload = new java.util.HashMap<>();
                        payload.put("serverRevision", (int) fractionalServerRevision);
                        payload.put("serverRevisionFractional", fractionalServerRevision);
                        publishEvent(new ZenyardEvent(ZenyardEvent.EventType.SERVER_REVISION_UPDATED, 
                            getTaskTitle(), payload));
                    } else {
                        Msg.debug(this, "Server revision unchanged: " + fractionalServerRevision + " (old: " + oldFractionalServerRevision + ")");
                    }
                    
                    // When paused, suppress analysis progress tracking entirely so
                    // the status bar doesn't misleadingly show "Analyzing in background".
                    if (paused) {
                        if (getRemoteAnalysisStats() != null) {
                            clearRemoteAnalysisStats();
                        }
                        publishAnalysisStatus(null, fractionalServerRevision);
                    } else {
                        // Track RemoteAnalysisStats when analysis starts
                        boolean isAnalyzing = (status.getRevisionAnalyses() != null && !status.getRevisionAnalyses().isEmpty());
                        Msg.debug(this, "PollServerStatusTask: isAnalyzing=" + isAnalyzing 
                            + ", revision_analyses=" + (status.getRevisionAnalyses() != null ? status.getRevisionAnalyses().size() : 0));
                        
                        // Check if analysis was in progress but server shows it's not analyzing anymore
                        if (!isAnalyzing && isAnalysisInProgress()) {
                            Msg.info(this, "PollServerStatusTask: Analysis completed while program was closed");
                            clearRemoteAnalysisStats();
                            setRemoteAnalysisCompletedOnce();
                            publishAnalysisStatus(null, fractionalServerRevision);
                        }
                        
                        if (isAnalyzing && getRemoteAnalysisStats() == null) {
                            setRemoteAnalysisStats(new RemoteAnalysisStats(System.currentTimeMillis(), fractionalServerRevision));
                            Msg.debug(this, "PollServerStatusTask: Analysis started, created RemoteAnalysisStats");
                        }
                        boolean hadAnalysisStats = (getRemoteAnalysisStats() != null);
                        
                        // Check if client is in sync with server (fractional compare, like IDA)
                        boolean clientInSync = Math.abs(localRevision - fractionalServerRevision) < REVISION_EPS;

                        if (clientInSync) {
                            setLastDoneRevision(localRevision);
                            if (getRemoteAnalysisStats() != null) {
                                clearRemoteAnalysisStats();
                            } else if (isAnalysisInProgress()) {
                                setAnalysisInProgress(false);
                                Msg.debug(this, "PollServerStatusTask: Analysis completed while program was closed, clearing flag");
                            }
                            int prevLocalRevision = localRevision;
                            waitForClientAhead(monitor, localRevision);
                            localRevision = getLocalRevision();

                            if (localRevision != prevLocalRevision) {
                                // Local revision advanced during wait — the server
                                // revision from this poll cycle is stale and must not
                                // be used for progress calculation.  Re-poll immediately
                                // so the next iteration works with fresh server data.
                                consecutiveConnectionFailures = 0;
                                updateConnectivity(true);
                                continue;
                            }
                        }
                        
                        AnalysisStatus analysisStatus = calculateAnalysisStatus(localRevision, fractionalServerRevision);
                        if (analysisStatus != null) {
                            Msg.debug(this, "PollServerStatusTask: Publishing ANALYSIS_STATUS_UPDATED, progress=" 
                                + analysisStatus.getProgress());
                            publishAnalysisStatus(analysisStatus, fractionalServerRevision);
                        } else if (clientInSync) {
                            if (hadAnalysisStats) {
                                Msg.debug(this, "PollServerStatusTask: Client in sync, signaling completion");
                                setRemoteAnalysisCompletedOnce();
                            }
                            publishAnalysisStatus(null, fractionalServerRevision);
                        } else {
                            Msg.debug(this, "PollServerStatusTask: No analysis status to publish");
                        }
                    }
                    
                    // Reset connection failure counter on successful poll
                    consecutiveConnectionFailures = 0;
                    updateConnectivity(true);
                    
                    // Wait before next poll
                    Thread.sleep(POLL_INTERVAL_MS);
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Exception e) {
                    // Handle connection errors with exponential backoff
                    if (ConnectionErrorHandler.isConnectionError(e)) {
                        Throwable rootCause = ConnectionErrorHandler.findRootCause(e);
                        int updatedFailures = consecutiveConnectionFailures + 1;
                        int backoffMs = ConnectionErrorHandler.calculateBackoff(
                            updatedFailures, INITIAL_BACKOFF_MS, MAX_BACKOFF_MS);
                        
                        Msg.warn(this, "Connection error polling server status: " + rootCause.getMessage() 
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
                        Msg.warn(this, "Error polling server status: " + e.getMessage());
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
            Msg.showError(this, tool.getActiveWindow(), "Polling Error",
                "Failed to poll server status: " + e.getMessage(), e);
        }
    }
    
    /**
     * Stop the polling task.
     */
    public void stop() {
        shouldStop = true;
    }
    
    /**
     * Wait for client to be ahead of server.
     */
    private void waitForClientAhead(TaskMonitor monitor, int currentRevision) {
        int waitCount = 0;
        while (!shouldStop && !monitor.isCancelled() && waitCount < 100) {
            int localRev = getLocalRevision();
            int serverRev = (int) getServerRevisionFractional();
            
            if (localRev > serverRev) {
                return; // Client is ahead
            }
            
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            waitCount++;
        }
    }
    
    /**
     * Get local revision number.
     */
    private int getLocalRevision() {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        Integer revision = props.getInt("revision");
        if (revision != null) {
            return revision;
        }
        return 1;
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
        // Default to 1.0 if not set
        return 1.0;
    }
    
    /**
     * Store fractional server revision for accurate progress calculation.
     */
    private void setServerRevisionFractional(double revision) {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        props.setString("server_revision_fractional", String.valueOf(revision));
    }
    
    /**
     * Calculates the fractional server revision based on the binary status.
     * Returns the full fractional value (e.g., 5.7) for accurate progress/ETA calculation.
     * 
     * @param status The binary status from the server
     * @param currentServerRevision The current server revision value
     * @param localRevision The local revision number
     * @return The calculated server revision as a double (fractional)
     */
    private double calculateServerRevisionFractional(BinaryStatus status, int currentServerRevision, int localRevision) {
        if (status.getRevisionAnalyses() != null && !status.getRevisionAnalyses().isEmpty()) {
            // Server is analyzing - calculate progress
            // Find max revision in progress
            int currentTargetRevision = status.getRevisionAnalyses().stream()
                .mapToInt(RevisionAnalysisStatus::getRevision)
                .max()
                .orElse(currentServerRevision);
            
            // Track the maximum server revision we've seen
            if (maxServerRevision == null || currentTargetRevision > maxServerRevision) {
                maxServerRevision = currentTargetRevision;
            }
            
            // Calculate progress: maxRevision - sum of missing progress for all analyses
            // Clamp each per-revision progress to [0,1] to guard against server-side
            // floating-point overshoot (e.g. 1.0000001) that would make missingProgress
            // negative and push the result past maxServerRevision.
            double missingProgress = status.getRevisionAnalyses().stream()
                .mapToDouble(ras -> 1.0 - Math.max(0.0, Math.min(1.0, ras.getProgress().doubleValue())))
                .sum();
            
            double result = maxServerRevision - missingProgress;
            return Math.max(0.0, Math.min(maxServerRevision, result));
        } else {
            // Server is idle - use local revision
            maxServerRevision = null;
            return localRevision;
        }
    }
    
    /**
     * Get last done revision (when client was last in sync with server).
     */
    private int getLastDoneRevision() {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        Integer revision = props.getInt("last_done_revision");
        if (revision != null) {
            return revision;
        }
        return 1;
    }
    
    /**
     * Set last done revision (when client syncs with server).
     */
    private void setLastDoneRevision(int revision) {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        props.setInt("last_done_revision", revision);
    }
    
    /**
     * Get RemoteAnalysisStats from properties.
     */
    private RemoteAnalysisStats getRemoteAnalysisStats() {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        String startTimeStr = props.getString("remote_analysis_start_time");
        String startRevisionStr = props.getString("remote_analysis_start_revision");
        
        if (startTimeStr == null || startRevisionStr == null 
            || startTimeStr.isEmpty() || startRevisionStr.isEmpty()) {
            return null;
        }
        
        try {
            long startTime = Long.parseLong(startTimeStr);
            double startRevision = Double.parseDouble(startRevisionStr);
            return new RemoteAnalysisStats(startTime, startRevision);
        } catch (NumberFormatException e) {
            return null;
        }
    }
    
    /**
     * Set RemoteAnalysisStats to properties.
     */
    private void setRemoteAnalysisStats(RemoteAnalysisStats stats) {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        props.setString("remote_analysis_start_time", String.valueOf(stats.getStartTime()));
        props.setString("remote_analysis_start_revision", String.valueOf(stats.getStartRevision()));
        // Mark analysis as in progress
        setAnalysisInProgress(true);
    }
    
    /**
     * Clear RemoteAnalysisStats from properties.
     */
    private void clearRemoteAnalysisStats() {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        // Clear by setting to empty string (properties will be treated as not set)
        props.setString("remote_analysis_start_time", "");
        props.setString("remote_analysis_start_revision", "");
        // Mark analysis as not in progress
        setAnalysisInProgress(false);
    }
    
    /**
     * Check if analysis is in progress (persisted state).
     */
    private boolean isAnalysisInProgress() {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        String flag = props.getString("analysis_in_progress");
        return "true".equals(flag);
    }
    
    /**
     * Set analysis in progress flag.
     */
    private void setAnalysisInProgress(boolean inProgress) {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        if (inProgress) {
            props.setString("analysis_in_progress", "true");
        } else {
            // Clear by setting to empty string
            props.setString("analysis_in_progress", "");
        }
    }

    /**
     * Persist that the binary has completed remote analysis at least once.
     * Used by change tracking to suppress CHANGES_DETECTED before first analysis.
     */
    private void setRemoteAnalysisCompletedOnce() {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        props.setString("remote_analysis_completed_once", "true");
    }
    
    /**
     * Calculate analysis status (progress).
     * Mirrors _get_analysis_status_sync() in zenyard_ida/ui/status_bar_view_model.py
     * 
     * @param localRevision Current local revision
     * @param serverRevision Fractional server revision
     * @return AnalysisStatus with progress, or null if analysis is not active
     */
    private AnalysisStatus calculateAnalysisStatus(int localRevision, double serverRevision) {
        int uploadedRevision = localRevision;
        
        if (Math.abs(uploadedRevision - serverRevision) < REVISION_EPS) {
            return null;
        }
        
        int revision = uploadedRevision;
        int lastDoneRevision = getLastDoneRevision();
        
        if (revision == lastDoneRevision) {
            return null;
        }
        
        double progress = (serverRevision - lastDoneRevision) / (revision - lastDoneRevision);
        progress = Math.max(0.0, Math.min(1.0, progress));
        
        return new AnalysisStatus(progress);
    }
    
    /**
     * Restore analysis state if it was in progress when the program was closed.
     * This allows the status bar to show "Analyzing in background" immediately on program activation,
     * before the first server poll completes.
     * 
     * However, if analysis completed while the program was closed (client is in sync),
     * we clear the state instead of restoring it.
     */
    private void restoreAnalysisStateIfNeeded() {
        if (!isAnalysisInProgress()) {
            Msg.debug(this, "PollServerStatusTask: No analysis in progress, skipping state restoration");
            return;
        }
        
        RemoteAnalysisStats stats = getRemoteAnalysisStats();
        if (stats == null) {
            Msg.debug(this, "PollServerStatusTask: Analysis in progress flag set but no stats found, clearing flag");
            setAnalysisInProgress(false);
            return;
        }
        
        // Get current state from properties
        int localRevision = getLocalRevision();
        double fractionalServerRevision = getServerRevisionFractional();
        
        // Check if client is already in sync with server - this indicates analysis completed
        // while the program was closed
        boolean clientInSync = Math.abs(localRevision - fractionalServerRevision) < REVISION_EPS;
        
        if (clientInSync) {
            // Analysis completed while program was closed - clear the state
            Msg.info(this, "PollServerStatusTask: Analysis completed while program was closed, clearing state");
            clearRemoteAnalysisStats(); // This also clears analysis_in_progress flag
            setRemoteAnalysisCompletedOnce();
            // Publish null status to unregister the status bar task
            publishAnalysisStatus(null, fractionalServerRevision);
            return;
        }
        
        Msg.info(this, "PollServerStatusTask: Restoring analysis state - analysis was in progress when program closed");
        
        // Calculate analysis status using stored state
        // Note: This uses the last known server_revision_fractional, which may be slightly stale
        // The first poll will update it, but this gives immediate feedback to the user
        AnalysisStatus analysisStatus = calculateAnalysisStatus(localRevision, fractionalServerRevision);
        
        if (analysisStatus != null) {
            Msg.debug(this, "PollServerStatusTask: Restored analysis status, progress=" 
                + analysisStatus.getProgress());
            publishAnalysisStatus(analysisStatus, fractionalServerRevision);
        } else {
            // Analysis may have completed while program was closed, or state is invalid
            // First poll will handle this properly
            Msg.debug(this, "PollServerStatusTask: Could not restore analysis status, will check on first poll");
        }
    }
    
    /**
     * Extract queue position from BinaryStatus and publish if changed.
     * Only called on successful getDetailedStatus responses (never on errors).
     */
    private void publishQueuePositionIfChanged(BinaryStatus status) {
        Integer queuePosition = extractQueuePosition(status);
        boolean changed = !hasPublishedQueuePosition
            || !java.util.Objects.equals(lastPublishedQueuePosition, queuePosition);
        if (!changed) {
            return;
        }
        lastPublishedQueuePosition = queuePosition;
        hasPublishedQueuePosition = true;

        java.util.Map<String, Object> payload = new java.util.HashMap<>();
        payload.put("queuePosition", queuePosition);
        publishEvent(new ZenyardEvent(ZenyardEvent.EventType.QUEUE_POSITION_UPDATED,
            getTaskTitle(), payload));
        Msg.debug(this, "PollServerStatusTask: Published QUEUE_POSITION_UPDATED, queuePosition=" + queuePosition);
    }

    static Integer extractQueuePosition(BinaryStatus status) {
        if (status == null) {
            return null;
        }
        BinaryState state = status.getState();
        if (state == null) {
            return null;
        }
        Object actual = state.getActualInstance();
        if (actual instanceof BinaryStateQueued) {
            return ((BinaryStateQueued) actual).getQueuePosition();
        }
        return null;
    }

    static boolean extractIsPaused(BinaryStatus status) {
        if (status == null) {
            return false;
        }
        BinaryState state = status.getState();
        if (state == null) {
            return false;
        }
        return state.getActualInstance() instanceof BinaryStatePaused;
    }

    /**
     * Extract paused state from BinaryStatus and publish if changed.
     * Persists the flag so the status bar can show paused immediately on restart.
     */
    private void publishPausedStateIfChanged(BinaryStatus status) {
        boolean paused = extractIsPaused(status);
        Boolean pausedBoxed = paused;
        boolean changed = !hasPublishedPaused
            || !java.util.Objects.equals(lastPublishedPaused, pausedBoxed);
        if (!changed) {
            return;
        }
        lastPublishedPaused = pausedBoxed;
        hasPublishedPaused = true;

        // Persist so StatusBarManager can check on restart before first poll
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        props.setString("binary_paused", paused ? "true" : "");

        java.util.Map<String, Object> payload = new java.util.HashMap<>();
        payload.put("paused", paused);
        publishEvent(new ZenyardEvent(ZenyardEvent.EventType.BINARY_PAUSED_UPDATED,
            getTaskTitle(), payload));
        Msg.debug(this, "PollServerStatusTask: Published BINARY_PAUSED_UPDATED, paused=" + paused);
    }

    /**
     * Publish analysis status event.
     * 
     * @param status Analysis status (can be null if analysis is not active)
     * @param serverRevision Current fractional server revision
     */
    private void publishAnalysisStatus(AnalysisStatus status, double serverRevision) {
        java.util.Map<String, Object> payload = new java.util.HashMap<>();
        
        if (status != null) {
            payload.put("progress", status.getProgress());
            payload.put("serverRevision", serverRevision);
        } else {
            // Publish null status to indicate analysis is not active
            payload.put("status", null);
        }
        
        publishEvent(new ZenyardEvent(ZenyardEvent.EventType.ANALYSIS_STATUS_UPDATED, 
            getTaskTitle(), payload));
    }

    private void verifyConnectivityOnce() {
        if (defaultApi == null) {
            Msg.debug(this, "PollServerStatusTask: DefaultApi not available, skipping connectivity check");
            return;
        }
        try {
            defaultApi.health();
            updateConnectivity(true);
        } catch (Exception e) {
            Throwable rootCause = ConnectionErrorHandler.findRootCause(e);
            if (rootCause instanceof ApiException) {
                ApiException apiException = (ApiException) rootCause;
                if (isConnectivityFailure(apiException)) {
                    updateConnectivity(false);
                } else {
                    Msg.warn(this, "Error verifying server connectivity: " + apiException.getMessage());
                }
            } else if (ConnectionErrorHandler.isConnectionError(e)) {
                updateConnectivity(false);
            } else {
                Msg.warn(this, "Error verifying server connectivity: " + e.getMessage());
            }
        }
    }

    private ApiClient cloneApiClient(ApiClient baseClient, int readTimeoutMs) {
        ApiClient client = new ApiClient();
        client.updateBaseUri(baseClient.getBaseUri());
        client.setRequestInterceptor(baseClient.getRequestInterceptor());
        client.setReadTimeout(Duration.ofMillis(readTimeoutMs));
        client.setConnectTimeout(Duration.ofMillis(readTimeoutMs));
        return client;
    }

    private boolean isConnectivityFailure(ApiException e) {
        if (ConnectionErrorHandler.isConnectionError(e)) {
            return true;
        }
        int statusCode = e.getCode();
        return statusCode == 0 || statusCode >= 500;
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
}
