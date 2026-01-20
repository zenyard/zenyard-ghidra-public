package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Base class for all inference types.
 * 
 * NOTE: mirrors models.inference.BaseInference in decompai/src/models/inference.py
 */
public abstract class BaseInference {
    @SerializedName("type")
    private String type;
    
    @SerializedName("address")
    private Address address;
    
    public BaseInference() {
        // Default constructor for Gson
    }
    
    public BaseInference(String type, Address address) {
        this.type = type;
        this.address = address;
    }
    
    public String getType() {
        return type;
    }
    
    public void setType(String type) {
        this.type = type;
    }
    
    public Address getAddress() {
        return address;
    }
    
    public void setAddress(Address address) {
        this.address = address;
    }
}

