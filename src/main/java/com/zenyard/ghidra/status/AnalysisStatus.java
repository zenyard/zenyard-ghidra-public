package com.zenyard.ghidra.status;

/**
 * Represents the current status of remote analysis, including progress and ETA.
 * Mirrors the _AnalysisStatus dataclass in zenyard_ida/ui/status_bar_view_model.py
 */
public class AnalysisStatus {
    private final double progress; // 0.0 to 1.0
    private final Double eta; // ETA in seconds, or null if not available
    
    public AnalysisStatus(double progress, Double eta) {
        this.progress = progress;
        this.eta = eta;
    }
    
    public double getProgress() {
        return progress;
    }
    
    public Double getEta() {
        return eta;
    }
}
