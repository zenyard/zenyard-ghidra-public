package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Inference for renaming a symbol/function.
 * 
 * NOTE: mirrors models.inference.Name in zenyard/src/models/inference.py
 */
public class Name extends BaseInference {
    @SerializedName("name")
    private String name;
    
    public Name() {
        super("name", null);
    }
    
    public Name(Address address, String name) {
        super("name", address);
        this.name = name;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
}

