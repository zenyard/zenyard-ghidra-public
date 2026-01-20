package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Line mapping for Swift function inference.
 * 
 * NOTE: mirrors models.inference.LineMapping in decompai/src/models/inference.py
 */
public class LineMapping {
    @SerializedName("first_inferred_line")
    private int firstInferredLine;
    
    @SerializedName("first_input_line_id")
    private String firstInputLineId;
    
    @SerializedName("last_input_line_id")
    private String lastInputLineId;
    
    public LineMapping() {
        // Default constructor for Gson
    }
    
    public LineMapping(int firstInferredLine, String firstInputLineId, String lastInputLineId) {
        this.firstInferredLine = firstInferredLine;
        this.firstInputLineId = firstInputLineId;
        this.lastInputLineId = lastInputLineId;
    }
    
    public int getFirstInferredLine() {
        return firstInferredLine;
    }
    
    public void setFirstInferredLine(int firstInferredLine) {
        this.firstInferredLine = firstInferredLine;
    }
    
    public String getFirstInputLineId() {
        return firstInputLineId;
    }
    
    public void setFirstInputLineId(String firstInputLineId) {
        this.firstInputLineId = firstInputLineId;
    }
    
    public String getLastInputLineId() {
        return lastInputLineId;
    }
    
    public void setLastInputLineId(String lastInputLineId) {
        this.lastInputLineId = lastInputLineId;
    }
}

