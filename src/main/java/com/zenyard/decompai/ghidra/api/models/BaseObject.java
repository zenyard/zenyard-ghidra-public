package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Base class for all objects (Function, Thunk, GlobalVariable, Section).
 * 
 * NOTE: mirrors models.binary.BaseObject in decompai/src/models/binary.py
 */
public abstract class BaseObject {
    @SerializedName("address")
    private Address address;
    
    @SerializedName("type")
    private String type;
    
    @SerializedName("name")
    private String name;
    
    @SerializedName("has_known_name")
    private boolean hasKnownName = false;
    
    @SerializedName("inference_seq_number")
    private int inferenceSeqNumber = 0;
    
    public BaseObject() {
        // Default constructor for Gson
    }
    
    public BaseObject(Address address, String type, String name, boolean hasKnownName, int inferenceSeqNumber) {
        this.address = address;
        this.type = type;
        this.name = name;
        this.hasKnownName = hasKnownName;
        this.inferenceSeqNumber = inferenceSeqNumber;
    }
    
    public Address getAddress() {
        return address;
    }
    
    public void setAddress(Address address) {
        this.address = address;
    }
    
    public String getType() {
        return type;
    }
    
    public void setType(String type) {
        this.type = type;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public boolean isHasKnownName() {
        return hasKnownName;
    }
    
    public void setHasKnownName(boolean hasKnownName) {
        this.hasKnownName = hasKnownName;
    }
    
    public int getInferenceSeqNumber() {
        return inferenceSeqNumber;
    }
    
    public void setInferenceSeqNumber(int inferenceSeqNumber) {
        this.inferenceSeqNumber = inferenceSeqNumber;
    }
}

