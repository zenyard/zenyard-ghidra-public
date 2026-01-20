package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Base class for range details (AddressDetail or LVarDetail).
 * Uses discriminator pattern for JSON deserialization.
 * 
 * NOTE: mirrors models.binary.RangeDetail in decompai/src/models/binary.py
 */
public abstract class RangeDetail {
    @SerializedName("type")
    private String type;
    
    public RangeDetail() {
        // Default constructor for Gson
    }
    
    public RangeDetail(String type) {
        this.type = type;
    }
    
    public String getType() {
        return type;
    }
    
    public void setType(String type) {
        this.type = type;
    }
}

