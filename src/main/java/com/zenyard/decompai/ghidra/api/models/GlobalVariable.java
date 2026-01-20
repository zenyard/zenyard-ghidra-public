package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Represents a global variable object.
 * 
 * NOTE: mirrors models.binary.GlobalVariable in decompai/src/models/binary.py
 */
public class GlobalVariable extends BaseObject {
    @SerializedName("uses")
    private List<Address> uses;
    
    @SerializedName("mangled_name")
    private String mangledName;
    
    public GlobalVariable() {
        super();
        setType("global_variable");
    }
    
    public GlobalVariable(Address address, String name, boolean hasKnownName, int inferenceSeqNumber,
                          List<Address> uses, String mangledName) {
        super(address, "global_variable", name, hasKnownName, inferenceSeqNumber);
        this.uses = uses;
        this.mangledName = mangledName;
    }
    
    public List<Address> getUses() {
        return uses;
    }
    
    public void setUses(List<Address> uses) {
        this.uses = uses;
    }
    
    public String getMangledName() {
        return mangledName;
    }
    
    public void setMangledName(String mangledName) {
        this.mangledName = mangledName;
    }
}

