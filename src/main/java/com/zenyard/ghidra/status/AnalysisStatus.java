package com.zenyard.ghidra.status;

/**
 * Represents the current status of remote analysis.
 * Mirrors the _AnalysisStatus dataclass in zenyard_ida/ui/status_bar_view_model.py
 */
public class AnalysisStatus {
    private final double progress; // 0.0 to 1.0

    public AnalysisStatus(double progress) {
        this.progress = progress;
    }

    public double getProgress() {
        return progress;
    }
}
