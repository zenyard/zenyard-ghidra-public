package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.UUID;

/**
 * Response from creating a binary.
 * 
 * NOTE: mirrors api.binaries.PostBinaryResponse in zenyard/src/api/binaries.py
 */
public class PostBinaryResponse {
    @SerializedName("binary_id")
    private UUID binaryId;
    
    public PostBinaryResponse() {
        // Default constructor for Gson
    }
    
    public PostBinaryResponse(UUID binaryId) {
        this.binaryId = binaryId;
    }
    
    public UUID getBinaryId() {
        return binaryId;
    }
    
    public void setBinaryId(UUID binaryId) {
        this.binaryId = binaryId;
    }
}

