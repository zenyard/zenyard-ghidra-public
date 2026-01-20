package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Programming languages the original binary was compiled from.
 * 
 * NOTE: mirrors models.binary.OriginalLanguages in decompai/src/models/binary.py
 */
public class OriginalLanguages {
    @SerializedName("swift")
    private boolean swift = false;
    
    public OriginalLanguages() {
        // Default constructor for Gson
    }
    
    public OriginalLanguages(boolean swift) {
        this.swift = swift;
    }
    
    public boolean isSwift() {
        return swift;
    }
    
    public void setSwift(boolean swift) {
        this.swift = swift;
    }
}

