package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Swift function inference (read-only).
 * 
 * NOTE: mirrors models.inference.SwiftFunction in decompai/src/models/inference.py
 */
public class SwiftFunction extends BaseInference {
    @SerializedName("source")
    private String source;
    
    @SerializedName("line_mappings")
    private List<LineMapping> lineMappings;
    
    @SerializedName("speculations")
    private List<SwiftSpeculation> speculations;
    
    public SwiftFunction() {
        super("swift_function", null);
    }
    
    public SwiftFunction(Address address, String source, List<LineMapping> lineMappings,
                        List<SwiftSpeculation> speculations) {
        super("swift_function", address);
        this.source = source;
        this.lineMappings = lineMappings;
        this.speculations = speculations != null ? speculations : List.of();
    }
    
    public String getSource() {
        return source;
    }
    
    public void setSource(String source) {
        this.source = source;
    }
    
    public List<LineMapping> getLineMappings() {
        return lineMappings;
    }
    
    public void setLineMappings(List<LineMapping> lineMappings) {
        this.lineMappings = lineMappings;
    }
    
    public List<SwiftSpeculation> getSpeculations() {
        return speculations;
    }
    
    public void setSpeculations(List<SwiftSpeculation> speculations) {
        this.speculations = speculations;
    }
}

