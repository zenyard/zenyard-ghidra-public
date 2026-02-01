package com.zenyard.ghidra.polling;

import java.util.HashSet;
import java.util.Set;
import java.time.Duration;
import java.util.UUID;

import com.zenyard.ghidra.api.generated.ApiClient;
import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.api.DefaultApi;
import com.zenyard.ghidra.api.generated.ApiException;
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
    private static final long ETA_CALCULATION_TIME_MS = 30_000L; // 30 seconds in milliseconds
    private static final long ETA_MIN_TIME_MS = 5_000L; // 5 seconds in milliseconds
    private static final double ETA_MIN_PROGRESS = 0.05; // 5% progress to allow early ETA
    private static final double REVISION_EPS = 1e-6; // floating point tolerance for revision comparisons
    private static final int CONNECTIVITY_CHECK_TIMEOUT_MS = 5000;
    private static final int STATUS_REQUEST_TIMEOUT_MS = 10000;
    
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
                    
                    // Track RemoteAnalysisStats when analysis starts
                    boolean isAnalyzing = (status.getRevisionAnalyses() != null && !status.getRevisionAnalyses().isEmpty());
                    Msg.debug(this, "PollServerStatusTask: isAnalyzing=" + isAnalyzing 
                        + ", revision_analyses=" + (status.getRevisionAnalyses() != null ? status.getRevisionAnalyses().size() : 0));
                    
                    // Check if analysis was in progress but server shows it's not analyzing anymore
                    // This handles the case where analysis completed while program was closed
                    if (!isAnalyzing && isAnalysisInProgress()) {
                        // Analysis flag says in progress, but server says not analyzing
                        // This means analysis completed while program was closed
                        Msg.info(this, "PollServerStatusTask: Analysis completed while program was closed");
                        clearRemoteAnalysisStats(); // This also clears analysis_in_progress flag
                        // Publish null status to clear the status bar immediately
                        publishAnalysisStatus(null, fractionalServerRevision);
                    }
                    
                    if (isAnalyzing && getRemoteAnalysisStats() == null) {
                        // Analysis just started - create stats with fractional revision for accuracy
                        // Use wall-clock time (milliseconds since epoch) for persistence across restarts
                        setRemoteAnalysisStats(new RemoteAnalysisStats(System.currentTimeMillis(), fractionalServerRevision));
                        Msg.debug(this, "PollServerStatusTask: Analysis started, created RemoteAnalysisStats");
                    }
                    boolean hadAnalysisStats = (getRemoteAnalysisStats() != null);
                    
                    // Check if client is in sync with server (fractional compare, like IDA)
                    boolean clientInSync = Math.abs(localRevision - fractionalServerRevision) < REVISION_EPS;

                    if (clientInSync) {
                        // Client is in sync - analysis has completed
                        // Store last_done_revision and clear stats
                        setLastDoneRevision(localRevision);
                        if (getRemoteAnalysisStats() != null) {
                            clearRemoteAnalysisStats(); // This also clears analysis_in_progress flag
                        } else if (isAnalysisInProgress()) {
                            // Stats were cleared but flag wasn't - clear it now
                            // This handles the case where analysis completed while program was closed
                            setAnalysisInProgress(false);
                            Msg.debug(this, "PollServerStatusTask: Analysis completed while program was closed, clearing flag");
                        }
                        // Wait for client to be ahead
                        waitForClientAhead(monitor, localRevision);
                        localRevision = getLocalRevision();
                    }
                    
                    // Calculate and publish analysis status (progress and ETA).
                    // IDA-style reactive completion: if calculateAnalysisStatus() returns null while we had stats
                    // and the client is in sync, signal completion by publishing a null status.
                    AnalysisStatus analysisStatus = calculateAnalysisStatus(localRevision, fractionalServerRevision);
                    if (analysisStatus != null) {
                        Msg.debug(this, "PollServerStatusTask: Publishing ANALYSIS_STATUS_UPDATED, progress=" 
                            + analysisStatus.getProgress() + ", eta=" + analysisStatus.getEta());
                        publishAnalysisStatus(analysisStatus, fractionalServerRevision);
                    } else if (clientInSync && hadAnalysisStats) {
                        Msg.debug(this, "PollServerStatusTask: Client in sync, signaling completion");
                        publishAnalysisStatus(null, fractionalServerRevision);
                    } else {
                        Msg.debug(this, "PollServerStatusTask: No analysis status to publish");
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
            double missingProgress = status.getRevisionAnalyses().stream()
                .mapToDouble(ras -> 1.0 - ras.getProgress().doubleValue())
                .sum();
            
            return maxServerRevision - missingProgress;
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
     * Calculate analysis status (progress and ETA).
     * Mirrors _get_analysis_status_sync() in zenyard_ida/ui/status_bar_view_model.py
     * 
     * @param localRevision Current local revision
     * @param serverRevision Fractional server revision
     * @return AnalysisStatus with progress and ETA, or null if analysis is not active
     */
    private AnalysisStatus calculateAnalysisStatus(int localRevision, double serverRevision) {
        // Get uploaded revision (current revision)
        int uploadedRevision = localRevision;
        
        // Check if no revision was uploaded yet - prefer showing "Uploading" over "Analyzing"
        if (Math.abs(uploadedRevision - serverRevision) < REVISION_EPS) {
            return null;
        }
        
        // Calculate target revision (assuming all queued revisions are uploaded)
        // In Ghidra, revisions are uploaded immediately when queued, so target = current revision
        int revision = uploadedRevision;
        int lastDoneRevision = getLastDoneRevision();
        
        // Avoid division by zero
        if (revision == lastDoneRevision) {
            return null;
        }
        
        // Calculate progress: (server_revision - last_done_revision) / (revision - last_done_revision)
        double progress = (serverRevision - lastDoneRevision) / (revision - lastDoneRevision);
        
        // Calculate ETA
        Double eta = calculateEta(revision, serverRevision);
        
        return new AnalysisStatus(progress, eta);
    }
    
    /**
     * Calculate ETA for analysis completion.
     * Mirrors _calculate_eta() in zenyard_ida/ui/status_bar_view_model.py
     * 
     * Uses wall-clock time (milliseconds since epoch) to handle program restarts correctly.
     * 
     * @param revision Target revision
     * @param serverRevision Current fractional server revision
     * @return ETA in seconds, or null if not available
     */
    private Double calculateEta(double revision, double serverRevision) {
        RemoteAnalysisStats stats = getRemoteAnalysisStats();
        if (stats == null) {
            return null;
        }
        
        // No progress yet
        if (stats.getStartRevision() == serverRevision) {
            return null;
        }
        
        // Calculate time since stats were created using wall-clock time
        // This handles program restarts correctly since we store absolute timestamps
        long currentTimeMs = System.currentTimeMillis();
        long startTimeMs = stats.getStartTime();
        long timeSinceStatsMs = currentTimeMs - startTimeMs;
        
        // Handle case where stored time might be in old format (nanoseconds)
        // If the stored time is unreasonably large (> year 2100 in milliseconds), it's likely nanoseconds
        // Convert it by dividing by 1e6, but this is a one-time migration
        if (startTimeMs > 4102444800000L) { // Year 2100 in milliseconds
            // Likely stored as nanoseconds (old format) - convert to milliseconds
            // For this calculation, we'll treat it as if it started now (can't recover exact time)
            // This will cause ETA to recalculate from current point
            Msg.debug(this, "PollServerStatusTask: Detected old timestamp format, treating as restart");
            return null; // Let it recalculate from current state
        }
        
        double timeSinceStatsSeconds = timeSinceStatsMs / 1000.0;
        
        // Calculate progress since stats were created
        double denominator = (revision - stats.getStartRevision());
        if (denominator <= 0.0) {
            return null;
        }
        double progressSinceStats = (serverRevision - stats.getStartRevision()) / denominator;
        
        // Need at least some progress and time to produce a stable ETA.
        if (progressSinceStats <= 0.0 || timeSinceStatsMs < ETA_MIN_TIME_MS) {
            return null;
        }
        
        // Allow early ETA once meaningful progress is observed; otherwise wait for stabilization.
        if (progressSinceStats < ETA_MIN_PROGRESS && timeSinceStatsMs < ETA_CALCULATION_TIME_MS) {
            return null;
        }
        
        // Calculate distance remaining and speed
        double distance = 1.0 - progressSinceStats;
        double speed = progressSinceStats / timeSinceStatsSeconds;
        
        // Avoid division by zero
        if (speed == 0.0) {
            return null;
        }
        
        // ETA = distance / speed
        return distance / speed;
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
                + analysisStatus.getProgress() + ", eta=" + analysisStatus.getEta());
            publishAnalysisStatus(analysisStatus, fractionalServerRevision);
        } else {
            // Analysis may have completed while program was closed, or state is invalid
            // First poll will handle this properly
            Msg.debug(this, "PollServerStatusTask: Could not restore analysis status, will check on first poll");
        }
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
            payload.put("eta", status.getEta());
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
