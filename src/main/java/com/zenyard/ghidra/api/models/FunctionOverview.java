package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Inference for function overview description.
 * 
 * NOTE: mirrors models.inference.FunctionOverview in zenyard/src/models/inference.py
 */
public class FunctionOverview extends BaseInference {
    @SerializedName("overview")
    private String overview;
    
    @SerializedName("full_description")
    private String fullDescription;
    
    public FunctionOverview() {
        super("function_overview", null);
    }
    
    public FunctionOverview(Address address, String overview, String fullDescription) {
        super("function_overview", address);
        this.overview = overview;
        this.fullDescription = fullDescription;
    }
    
    public String getOverview() {
        return overview;
    }
    
    public void setOverview(String overview) {
        this.overview = overview;
    }
    
    public String getFullDescription() {
        return fullDescription;
    }
    
    public void setFullDescription(String fullDescription) {
        this.fullDescription = fullDescription;
    }
}

