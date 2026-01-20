package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Represents a thunk object.
 * 
 * NOTE: mirrors models.binary.Thunk in decompai/src/models/binary.py
 */
public class Thunk extends BaseObject {
    @SerializedName("target")
    private Address target;
    
    public Thunk() {
        super();
        setType("thunk");
    }
    
    public Thunk(Address address, String name, boolean hasKnownName, int inferenceSeqNumber, Address target) {
        super(address, "thunk", name, hasKnownName, inferenceSeqNumber);
        this.target = target;
    }
    
    public Address getTarget() {
        return target;
    }
    
    public void setTarget(Address target) {
        this.target = target;
    }
}

