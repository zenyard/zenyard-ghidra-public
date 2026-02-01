package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.Map;

/**
 * Inference for renaming local variables.
 * 
 * NOTE: mirrors models.inference.VariablesMapping in zenyard/src/models/inference.py
 */
public class VariablesMapping extends BaseInference {
    @SerializedName("variables_mapping")
    private Map<String, String> variablesMapping;
    
    public VariablesMapping() {
        super("variables", null);
    }
    
    public VariablesMapping(Address address, Map<String, String> variablesMapping) {
        super("variables", address);
        this.variablesMapping = variablesMapping;
    }
    
    public Map<String, String> getVariablesMapping() {
        return variablesMapping;
    }
    
    public void setVariablesMapping(Map<String, String> variablesMapping) {
        this.variablesMapping = variablesMapping;
    }
}

