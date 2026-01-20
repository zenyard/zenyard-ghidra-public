package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * A note from the decompiler.
 * 
 * NOTE: mirrors models.binary.DecompilerNote in decompai/src/models/binary.py
 */
public class DecompilerNote {
    @SerializedName("line_number")
    private int lineNumber;
    
    @SerializedName("text")
    private String text;
    
    public DecompilerNote() {
        // Default constructor for Gson
    }
    
    public DecompilerNote(int lineNumber, String text) {
        this.lineNumber = lineNumber;
        this.text = text;
    }
    
    public int getLineNumber() {
        return lineNumber;
    }
    
    public void setLineNumber(int lineNumber) {
        this.lineNumber = lineNumber;
    }
    
    public String getText() {
        return text;
    }
    
    public void setText(String text) {
        this.text = text;
    }
}

