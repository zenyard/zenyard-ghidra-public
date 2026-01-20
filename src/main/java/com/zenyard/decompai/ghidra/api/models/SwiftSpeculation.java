package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Swift speculation for Swift function inference.
 * 
 * NOTE: mirrors models.inference.SwiftSpeculation in decompai/src/models/inference.py
 */
public class SwiftSpeculation {
    @SerializedName("source_line_numbers")
    private List<Integer> sourceLineNumbers;
    
    @SerializedName("description")
    private String description;
    
    @SerializedName("is_trivial")
    private boolean isTrivial;
    
    public SwiftSpeculation() {
        // Default constructor for Gson
    }
    
    public SwiftSpeculation(List<Integer> sourceLineNumbers, String description, boolean isTrivial) {
        this.sourceLineNumbers = sourceLineNumbers;
        this.description = description;
        this.isTrivial = isTrivial;
    }
    
    public List<Integer> getSourceLineNumbers() {
        return sourceLineNumbers;
    }
    
    public void setSourceLineNumbers(List<Integer> sourceLineNumbers) {
        this.sourceLineNumbers = sourceLineNumbers;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public boolean isTrivial() {
        return isTrivial;
    }
    
    public void setTrivial(boolean trivial) {
        isTrivial = trivial;
    }
}

