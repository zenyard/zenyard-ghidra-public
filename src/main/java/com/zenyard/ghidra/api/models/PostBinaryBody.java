package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Request body for creating a binary.
 * 
 * NOTE: mirrors api.binaries.PostBinaryBody in zenyard/src/api/binaries.py
 */
public class PostBinaryBody {
    @SerializedName("name")
    private String name = "unknown";
    
    @SerializedName("details")
    private BinaryDetails details = new BinaryDetails();
    
    public PostBinaryBody() {
        // Default constructor for Gson
    }
    
    public PostBinaryBody(String name, BinaryDetails details) {
        this.name = name != null ? name : "unknown";
        this.details = details != null ? details : new BinaryDetails();
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name != null ? name : "unknown";
    }
    
    public BinaryDetails getDetails() {
        return details;
    }
    
    public void setDetails(BinaryDetails details) {
        this.details = details != null ? details : new BinaryDetails();
    }
}

