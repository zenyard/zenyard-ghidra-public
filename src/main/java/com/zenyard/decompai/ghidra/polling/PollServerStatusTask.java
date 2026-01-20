package com.zenyard.decompai.ghidra.polling;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import com.zenyard.decompai.ghidra.api.generated.api.BinariesApi;
import com.zenyard.decompai.ghidra.api.generated.model.BinaryStatus;
import com.zenyard.decompai.ghidra.api.generated.model.RevisionAnalysisStatus;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.events.EventConsumer;
import com.zenyard.decompai.ghidra.events.EventDispatcher;
import com.zenyard.decompai.ghidra.events.EventProducer;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;
import com.zenyard.decompai.ghidra.status.AnalysisStatus;
import com.zenyard.decompai.ghidra.status.RemoteAnalysisStats;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Background task that polls server for analysis status every 3 seconds.
 * 
 * NOTE: mirrors decompai_ida/poll_server_status_task.py
 */
public class PollServerStatusTask extends Task implements EventConsumer, EventProducer {
    
    private static final int POLL_INTERVAL_MS = 3000; // 3 seconds
    private static final int MAX_BACKOFF_MS = 30000; // Maximum backoff of 30 seconds
    private static final int INITIAL_BACKOFF_MS = 1000; // Initial backoff of 1 second
    private static final long ETA_CALCULATION_TIME_NS = 30_000_000_000L; // 30 seconds in nanoseconds
    private static final long ETA_MIN_TIME_NS = 5_000_000_000L; // 5 seconds in nanoseconds
    private static final double ETA_MIN_PROGRESS = 0.05; // 5% progress to allow early ETA
    private static final double REVISION_EPS = 1e-6; // floating point tolerance for revision comparisons
    
    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final Program program;
    private final EventDispatcher eventDispatcher;
    private volatile boolean shouldStop = false;
    private Integer maxServerRevision = null;
    private int consecutiveConnectionFailures = 0;
    
    // Event-based binary ID waiting
    private final Object waitLock = new Object();
    private volatile boolean binaryIdAvailable = false;
    private UUID binaryId = null;
    
    public PollServerStatusTask(PluginTool tool, BinariesApi binariesApi, Program program, EventDispatcher eventDispatcher) {
        super("Poll Server Status", true, false, false); // canCancel=true, hasProgress=false, isModal=false
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.program = program;
        this.eventDispatcher = eventDispatcher;
    }
    
    @Override
    public Set<DecompaiEvent.EventType> getSubscribedEventTypes() {
        Set<DecompaiEvent.EventType> types = new HashSet<>();
        types.add(DecompaiEvent.EventType.PROGRAM_DEACTIVATED);
        types.add(DecompaiEvent.EventType.BINARY_ID_AVAILABLE);
        return types;
    }
    
    @Override
    public void handleEvent(DecompaiEvent event) {
        if (event.getType() == DecompaiEvent.EventType.PROGRAM_DEACTIVATED) {
            shouldStop = true;
        } else if (event.getType() == DecompaiEvent.EventType.BINARY_ID_AVAILABLE) {
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
                DecompaiProgramProperties props = new DecompaiProgramProperties(program);
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
            // Wait for BINARY_ID_AVAILABLE event
            synchronized (waitLock) {
                while (!binaryIdAvailable && !shouldStop && !monitor.isCancelled()) {
                    // Check if binary ID is already available
                    DecompaiProgramProperties props = new DecompaiProgramProperties(program);
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
            
            int localRevision = getLocalRevision();
            double fractionalServerRevision = getServerRevisionFractional();
            
            while (!shouldStop && !monitor.isCancelled()) {
                try {
                    // Poll server status
                    BinaryStatus status = CompletableFuture.supplyAsync(() -> {
                        try {
                            return binariesApi.getDetailedStatus(binaryId);
                        } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                            throw new RuntimeException(e);
                        }
                    }).get();
                    
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
                        publishEvent(new DecompaiEvent(DecompaiEvent.EventType.SERVER_REVISION_UPDATED, 
                            getTaskTitle(), payload));
                    } else {
                        Msg.debug(this, "Server revision unchanged: " + fractionalServerRevision + " (old: " + oldFractionalServerRevision + ")");
                    }
                    
                    // Track RemoteAnalysisStats when analysis starts
                    boolean isAnalyzing = (status.getRevisionAnalyses() != null && !status.getRevisionAnalyses().isEmpty());
                    Msg.debug(this, "PollServerStatusTask: isAnalyzing=" + isAnalyzing + 
                        ", revision_analyses=" + (status.getRevisionAnalyses() != null ? status.getRevisionAnalyses().size() : 0));
                    if (isAnalyzing && getRemoteAnalysisStats() == null) {
                        // Analysis just started - create stats with fractional revision for accuracy
                        setRemoteAnalysisStats(new RemoteAnalysisStats(System.nanoTime(), fractionalServerRevision));
                        Msg.debug(this, "PollServerStatusTask: Analysis started, created RemoteAnalysisStats");
                    }
                    boolean hadAnalysisStats = (getRemoteAnalysisStats() != null);
                    
                    // Check if client is in sync with server (fractional compare, like IDA)
                    boolean clientInSync = Math.abs(localRevision - fractionalServerRevision) < REVISION_EPS;

                    if (clientInSync) {
                        // Client is in sync - store last_done_revision and clear stats
                        setLastDoneRevision(localRevision);
                        if (getRemoteAnalysisStats() != null) {
                            clearRemoteAnalysisStats();
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
                        Msg.debug(this, "PollServerStatusTask: Publishing ANALYSIS_STATUS_UPDATED, progress=" + 
                            analysisStatus.getProgress() + ", eta=" + analysisStatus.getEta());
                        publishAnalysisStatus(analysisStatus, fractionalServerRevision);
                    } else if (clientInSync && hadAnalysisStats) {
                        Msg.debug(this, "PollServerStatusTask: Client in sync, signaling completion");
                        publishAnalysisStatus(null, fractionalServerRevision);
                    } else {
                        Msg.debug(this, "PollServerStatusTask: No analysis status to publish");
                    }
                    
                    // Reset connection failure counter on successful poll
                    consecutiveConnectionFailures = 0;
                    
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
                        
                        Msg.warn(this, "Connection error polling server status: " + rootCause.getMessage() + 
                            " (attempt " + updatedFailures + ", backoff " + backoffMs + "ms)");
                        
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
        } finally {
            // Unsubscribe from events
            if (eventDispatcher != null) {
                eventDispatcher.unsubscribe(this);
            }
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
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        Integer revision = props.getInt("revision");
        if (revision != null) {
            return revision;
        }
        return 1;
    }
    
    /**
     * Get server revision number (derived from fractional value).
     * This method exists for backward compatibility with code that expects integer.
     */
    private int getServerRevision() {
        return (int) getServerRevisionFractional();
    }
    
    /**
     * Get fractional server revision from properties.
     * This is the source of truth - only fractional value is stored (like Python version).
     */
    private double getServerRevisionFractional() {
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
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
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
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
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
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
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        props.setInt("last_done_revision", revision);
    }
    
    /**
     * Get RemoteAnalysisStats from properties.
     */
    private RemoteAnalysisStats getRemoteAnalysisStats() {
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        String startTimeStr = props.getString("remote_analysis_start_time");
        String startRevisionStr = props.getString("remote_analysis_start_revision");
        
        if (startTimeStr == null || startRevisionStr == null || 
            startTimeStr.isEmpty() || startRevisionStr.isEmpty()) {
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
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        props.setString("remote_analysis_start_time", String.valueOf(stats.getStartTime()));
        props.setString("remote_analysis_start_revision", String.valueOf(stats.getStartRevision()));
    }
    
    /**
     * Clear RemoteAnalysisStats from properties.
     */
    private void clearRemoteAnalysisStats() {
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        // Clear by setting to empty string (properties will be treated as not set)
        props.setString("remote_analysis_start_time", "");
        props.setString("remote_analysis_start_revision", "");
    }
    
    /**
     * Calculate analysis status (progress and ETA).
     * Mirrors _get_analysis_status_sync() in decompai_ida/ui/status_bar_view_model.py
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
     * Mirrors _calculate_eta() in decompai_ida/ui/status_bar_view_model.py
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
        
        // Calculate time since stats were created
        long timeSinceStatsNs = System.nanoTime() - stats.getStartTime();
        
        double timeSinceStatsSeconds = timeSinceStatsNs / 1e9;
        
        // Calculate progress since stats were created
        double denominator = (revision - stats.getStartRevision());
        if (denominator <= 0.0) {
            return null;
        }
        double progressSinceStats = (serverRevision - stats.getStartRevision()) / denominator;
        
        // Need at least some progress and time to produce a stable ETA.
        if (progressSinceStats <= 0.0 || timeSinceStatsNs < ETA_MIN_TIME_NS) {
            return null;
        }
        
        // Allow early ETA once meaningful progress is observed; otherwise wait for stabilization.
        if (progressSinceStats < ETA_MIN_PROGRESS && timeSinceStatsNs < ETA_CALCULATION_TIME_NS) {
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
        
        publishEvent(new DecompaiEvent(DecompaiEvent.EventType.ANALYSIS_STATUS_UPDATED, 
            getTaskTitle(), payload));
    }
}
