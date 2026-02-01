package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Represents a range in code with a detail (address or local variable).
 * 
 * NOTE: mirrors models.binary.Range in zenyard/src/models/binary.py
 */
public class Range {
    @SerializedName("start")
    private int start;
    
    @SerializedName("length")
    private int length;
    
    @SerializedName("detail")
    private RangeDetail detail;
    
    public Range() {
        // Default constructor for Gson
    }
    
    public Range(int start, int length, RangeDetail detail) {
        this.start = start;
        this.length = length;
        this.detail = detail;
    }
    
    public int getStart() {
        return start;
    }
    
    public void setStart(int start) {
        this.start = start;
    }
    
    public int getLength() {
        return length;
    }
    
    public void setLength(int length) {
        this.length = length;
    }
    
    public RangeDetail getDetail() {
        return detail;
    }
    
    public void setDetail(RangeDetail detail) {
        this.detail = detail;
    }
}

