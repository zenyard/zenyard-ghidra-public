package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Sets a client-side stable ID for a range for consecutive lines.
 * 
 * NOTE: mirrors models.binary.LineRange in decompai/src/models/binary.py
 */
public class LineRange {
    @SerializedName("line_count")
    private int lineCount;
    
    @SerializedName("id")
    private String id;
    
    public LineRange() {
        // Default constructor for Gson
    }
    
    public LineRange(int lineCount, String id) {
        this.lineCount = lineCount;
        this.id = id;
    }
    
    public int getLineCount() {
        return lineCount;
    }
    
    public void setLineCount(int lineCount) {
        this.lineCount = lineCount;
    }
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
}

