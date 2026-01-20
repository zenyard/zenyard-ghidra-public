package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Binary analysis is in progress.
 * 
 * NOTE: mirrors api.binaries.BinaryAnalysisInProgress in decompai/src/api/binaries.py
 */
public class BinaryAnalysisInProgress {
    @SerializedName("state")
    private String state = "analyzing";
    
    @SerializedName("revision")
    private int revision;
    
    @SerializedName("progress")
    private double progress;
    
    public BinaryAnalysisInProgress() {
        // Default constructor for Gson
    }
    
    public BinaryAnalysisInProgress(int revision, double progress) {
        this.state = "analyzing";
        this.revision = revision;
        this.progress = progress;
    }
    
    public String getState() {
        return state;
    }
    
    public void setState(String state) {
        this.state = state;
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

