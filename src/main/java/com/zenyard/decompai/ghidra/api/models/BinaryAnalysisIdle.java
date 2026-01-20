package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Binary analysis is idle (no analysis in progress).
 * 
 * NOTE: mirrors api.binaries.BinaryAnalysisIdle in decompai/src/api/binaries.py
 */
public class BinaryAnalysisIdle {
    @SerializedName("state")
    private String state = "idle";
    
    public BinaryAnalysisIdle() {
        // Default constructor for Gson
    }
    
    public String getState() {
        return state;
    }
    
    public void setState(String state) {
        this.state = state;
    }
}

