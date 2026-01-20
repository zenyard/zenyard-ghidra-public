package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Represents a section object.
 * 
 * NOTE: mirrors models.binary.Section in decompai/src/models/binary.py
 */
public class Section extends BaseObject {
    @SerializedName("size")
    private int size;
    
    @SerializedName("class")
    private String class_; // "code", "data", or "other"
    
    @SerializedName("read")
    private boolean read;
    
    @SerializedName("write")
    private boolean write;
    
    @SerializedName("execute")
    private boolean execute;
    
    public Section() {
        super();
        setType("section");
    }
    
    public Section(Address address, String name, boolean hasKnownName, int inferenceSeqNumber,
                   int size, String class_, boolean read, boolean write, boolean execute) {
        super(address, "section", name, hasKnownName, inferenceSeqNumber);
        this.size = size;
        this.class_ = class_;
        this.read = read;
        this.write = write;
        this.execute = execute;
    }
    
    public int getSize() {
        return size;
    }
    
    public void setSize(int size) {
        this.size = size;
    }
    
    public String getClass_() {
        return class_;
    }
    
    public void setClass_(String class_) {
        this.class_ = class_;
    }
    
    public boolean isRead() {
        return read;
    }
    
    public void setRead(boolean read) {
        this.read = read;
    }
    
    public boolean isWrite() {
        return write;
    }
    
    public void setWrite(boolean write) {
        this.write = write;
    }
    
    public boolean isExecute() {
        return execute;
    }
    
    public void setExecute(boolean execute) {
        this.execute = execute;
    }
}

