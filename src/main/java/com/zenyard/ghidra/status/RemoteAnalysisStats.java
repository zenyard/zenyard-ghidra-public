package com.zenyard.ghidra.status;

/**
 * Tracks statistics for remote analysis to calculate ETA.
 * Similar to zenyard_ida/model.py RemoteAnalysisStats.
 * 
 * Stores:
 * - startTime: when analysis started (milliseconds since epoch from System.currentTimeMillis())
 *   Uses wall-clock time to persist correctly across program restarts.
 * - startRevision: server revision when analysis started (fractional)
 */
public class RemoteAnalysisStats {
    private final long startTime;
    private final double startRevision;
    
    public RemoteAnalysisStats(long startTime, double startRevision) {
        this.startTime = startTime;
        this.startRevision = startRevision;
    }
    
    public long getStartTime() {
        return startTime;
    }
    
    public double getStartRevision() {
        return startRevision;
    }
}
