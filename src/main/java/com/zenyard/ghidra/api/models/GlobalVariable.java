package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Represents a global variable object.
 * 
 * NOTE: mirrors models.binary.GlobalVariable in zenyard/src/models/binary.py
 */
public class GlobalVariable extends BaseObject {
    @SerializedName("uses")
    private List<Address> uses;
    
    @SerializedName("mangled_name")
    private String mangledName;

    /** Declared size in the binary image (bytes), when known. Mirrors {@code size_bytes} in binary.py. */
    @SerializedName("size_bytes")
    private Integer sizeBytes;
    
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

    public Integer getSizeBytes() {
        return sizeBytes;
    }

    public void setSizeBytes(Integer sizeBytes) {
        this.sizeBytes = sizeBytes;
    }
}

