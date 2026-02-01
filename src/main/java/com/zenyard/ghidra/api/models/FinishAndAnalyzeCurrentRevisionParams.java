package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Parameters for finishing and analyzing the current revision.
 * 
 * NOTE: mirrors binary.api.FinishAndAnalyzeCurrentRevisionParams in zenyard/src/binary/api.py
 */
public class FinishAndAnalyzeCurrentRevisionParams {
    @SerializedName("analyze_dependents")
    private boolean analyzeDependents = true;
    
    public FinishAndAnalyzeCurrentRevisionParams() {
        // Default constructor for Gson
    }
    
    public FinishAndAnalyzeCurrentRevisionParams(boolean analyzeDependents) {
        this.analyzeDependents = analyzeDependents;
    }
    
    public boolean isAnalyzeDependents() {
        return analyzeDependents;
    }
    
    public void setAnalyzeDependents(boolean analyzeDependents) {
        this.analyzeDependents = analyzeDependents;
    }
}

