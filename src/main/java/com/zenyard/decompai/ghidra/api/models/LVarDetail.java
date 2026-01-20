package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Range detail for a local variable.
 * 
 * NOTE: mirrors models.binary.LVarDetail in decompai/src/models/binary.py
 */
public class LVarDetail extends RangeDetail {
    @SerializedName("name")
    private String name;
    
    @SerializedName("is_arg")
    private boolean isArg;
    
    public LVarDetail() {
        super("lvar");
    }
    
    public LVarDetail(String name, boolean isArg) {
        super("lvar");
        this.name = name;
        this.isArg = isArg;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public boolean isArg() {
        return isArg;
    }
    
    public void setArg(boolean arg) {
        isArg = arg;
    }
}

