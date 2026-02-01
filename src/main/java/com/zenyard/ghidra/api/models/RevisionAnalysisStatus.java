package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Status of analysis for a specific revision.
 * 
 * NOTE: mirrors binary.api.RevisionAnalysisStatus in zenyard/src/binary/api.py
 */
public class RevisionAnalysisStatus {
    @SerializedName("revision")
    private int revision;
    
    @SerializedName("progress")
    private double progress;
    
    public RevisionAnalysisStatus() {
        // Default constructor for Gson
    }
    
    public RevisionAnalysisStatus(int revision, double progress) {
        this.revision = revision;
        this.progress = progress;
    }
    
    public int getRevision() {
        return revision;
    }
    
    public void setRevision(int revision) {
        this.revision = revision;
    }
    
    public double getProgress() {
        return progress;
    }
    
    public void setProgress(double progress) {
        this.progress = progress;
    }
}

