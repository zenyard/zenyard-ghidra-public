package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Binary-level parameters. Fixed at binary creation time.
 * 
 * NOTE: mirrors models.binary.BinaryDetails in zenyard/src/models/binary.py
 */
public class BinaryDetails {
    @SerializedName("instructions")
    private String instructions;
    
    @SerializedName("original_languages")
    private OriginalLanguages originalLanguages = new OriginalLanguages();
    
    @SerializedName("platform")
    private String platform; // "ios" or "macos"
    
    @SerializedName("os_version")
    private String osVersion;
    
    public BinaryDetails() {
        // Default constructor for Gson
    }
    
    public BinaryDetails(String instructions, OriginalLanguages originalLanguages, 
                         String platform, String osVersion) {
        this.instructions = instructions;
        this.originalLanguages = originalLanguages != null ? originalLanguages : new OriginalLanguages();
        this.platform = platform;
        this.osVersion = osVersion;
    }
    
    public String getInstructions() {
        return instructions;
    }
    
    public void setInstructions(String instructions) {
        this.instructions = instructions;
    }
    
    public OriginalLanguages getOriginalLanguages() {
        return originalLanguages;
    }
    
    public void setOriginalLanguages(OriginalLanguages originalLanguages) {
        this.originalLanguages = originalLanguages != null ? originalLanguages : new OriginalLanguages();
    }
    
    public String getPlatform() {
        return platform;
    }
    
    public void setPlatform(String platform) {
        this.platform = platform;
    }
    
    public String getOsVersion() {
        return osVersion;
    }
    
    public void setOsVersion(String osVersion) {
        this.osVersion = osVersion;
    }
}

