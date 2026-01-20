package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.Map;

/**
 * Inference for renaming function parameters.
 * 
 * NOTE: mirrors models.inference.ParametersMapping in decompai/src/models/inference.py
 */
public class ParametersMapping extends BaseInference {
    @SerializedName("parameters_mapping")
    private Map<String, String> parametersMapping;
    
    public ParametersMapping() {
        super("params", null);
    }
    
    public ParametersMapping(Address address, Map<String, String> parametersMapping) {
        super("params", address);
        this.parametersMapping = parametersMapping;
    }
    
    public Map<String, String> getParametersMapping() {
        return parametersMapping;
    }
    
    public void setParametersMapping(Map<String, String> parametersMapping) {
        this.parametersMapping = parametersMapping;
    }
}

