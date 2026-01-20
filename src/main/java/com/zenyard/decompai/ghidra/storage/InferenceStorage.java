package com.zenyard.decompai.ghidra.storage;

import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import com.zenyard.decompai.ghidra.api.generated.model.ParametersMapping;
import com.zenyard.decompai.ghidra.api.generated.model.VariablesMapping;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Higher-level abstraction over DecompaiProgramProperties for managing storage of 
 * inferences, variable mappings, and analysis state.
 * 
 * Uses JSON serialization (Gson) for complex data structures.
 * 
 * NOTE: This replaces the complex storage system in decompai_ida/storage.py
 * which had to work around IDA's 1024-byte blob limit.
 */
public class InferenceStorage {
    
    private static final String INFERENCE_PREFIX = "inference.";
    private static final String VARIABLE_PREFIX = "variable.";
    private static final String ANALYSIS_STATE_KEY = "analysis_state";
    
    private final DecompaiProgramProperties properties;
    private final Gson gson;
    
    public InferenceStorage(Program program) {
        this.properties = new DecompaiProgramProperties(program);
        this.gson = new GsonBuilder().setPrettyPrinting().create();
    }
    
    /**
     * Data class for inference information.
     */
    public static class InferenceData {
        private String inferenceId;
        private String type;
        private Map<String, Object> data;
        
        public InferenceData() {
            this.data = new HashMap<>();
        }
        
        public InferenceData(String inferenceId, String type, Map<String, Object> data) {
            this.inferenceId = inferenceId;
            this.type = type;
            this.data = data != null ? data : new HashMap<>();
        }
        
        public String getInferenceId() {
            return inferenceId;
        }
        
        public void setInferenceId(String inferenceId) {
            this.inferenceId = inferenceId;
        }
        
        public String getType() {
            return type;
        }
        
        public void setType(String type) {
            this.type = type;
        }
        
        public Map<String, Object> getData() {
            return data;
        }
        
        public void setData(Map<String, Object> data) {
            this.data = data;
        }
    }
    
    /**
     * Data class for variable mapping.
     */
    public static class VariableMapping {
        private Address address;
        private String originalName;
        private String inferredName;
        
        public VariableMapping() {
        }
        
        public VariableMapping(Address address, String originalName, String inferredName) {
            this.address = address;
            this.originalName = originalName;
            this.inferredName = inferredName;
        }
        
        public Address getAddress() {
            return address;
        }
        
        public void setAddress(Address address) {
            this.address = address;
        }
        
        public String getOriginalName() {
            return originalName;
        }
        
        public void setOriginalName(String originalName) {
            this.originalName = originalName;
        }
        
        public String getInferredName() {
            return inferredName;
        }
        
        public void setInferredName(String inferredName) {
            this.inferredName = inferredName;
        }
    }
    
    /**
     * Data class for analysis state.
     */
    public static class AnalysisState {
        private boolean uploadComplete;
        private boolean analysisComplete;
        private String status;
        
        public AnalysisState() {
            this.uploadComplete = false;
            this.analysisComplete = false;
            this.status = "pending";
        }
        
        public AnalysisState(boolean uploadComplete, boolean analysisComplete, String status) {
            this.uploadComplete = uploadComplete;
            this.analysisComplete = analysisComplete;
            this.status = status;
        }
        
        public boolean isUploadComplete() {
            return uploadComplete;
        }
        
        public void setUploadComplete(boolean uploadComplete) {
            this.uploadComplete = uploadComplete;
        }
        
        public boolean isAnalysisComplete() {
            return analysisComplete;
        }
        
        public void setAnalysisComplete(boolean analysisComplete) {
            this.analysisComplete = analysisComplete;
        }
        
        public String getStatus() {
            return status;
        }
        
        public void setStatus(String status) {
            this.status = status;
        }
    }
    
    /**
     * Store an inference.
     */
    public void storeInference(String inferenceId, InferenceData data) {
        String key = INFERENCE_PREFIX + inferenceId;
        String json = gson.toJson(data);
        properties.setString(key, json);
    }
    
    /**
     * Get an inference.
     */
    public InferenceData getInference(String inferenceId) {
        String key = INFERENCE_PREFIX + inferenceId;
        String json = properties.getString(key);
        if (json == null || json.isEmpty()) {
            return null;
        }
        return gson.fromJson(json, InferenceData.class);
    }
    
    /**
     * Store a variable mapping.
     */
    public void storeVariableMapping(Address address, String variableName, String inferredName) {
        String key = VARIABLE_PREFIX + address.toString();
        VariableMapping mapping = new VariableMapping(address, variableName, inferredName);
        String json = gson.toJson(mapping);
        properties.setString(key, json);
    }
    
    /**
     * Get variable mappings.
     */
    public Map<Address, VariableMapping> getVariableMappings() {
        Map<Address, VariableMapping> mappings = new HashMap<>();
        // Note: In a full implementation, we would iterate over all properties
        // with the VARIABLE_PREFIX. For now, this is a placeholder structure.
        // We would need to extend DecompaiProgramProperties to support iteration.
        return mappings;
    }
    
    /**
     * Store analysis state.
     */
    public void storeAnalysisState(AnalysisState state) {
        String json = gson.toJson(state);
        properties.setString(ANALYSIS_STATE_KEY, json);
    }
    
    /**
     * Get analysis state.
     */
    public AnalysisState getAnalysisState() {
        String json = properties.getString(ANALYSIS_STATE_KEY);
        if (json == null || json.isEmpty()) {
            return new AnalysisState();
        }
        return gson.fromJson(json, AnalysisState.class);
    }
    
    /**
     * Store last variables mapping for an address.
     */
    public void storeLastVariablesMapping(Address address, VariablesMapping mapping) {
        String key = VARIABLE_PREFIX + "last." + address.toString();
        String json = gson.toJson(mapping);
        properties.setString(key, json);
    }
    
    /**
     * Get last variables mapping for an address.
     */
    public VariablesMapping getLastVariablesMapping(Address address) {
        String key = VARIABLE_PREFIX + "last." + address.toString();
        String json = properties.getString(key);
        if (json == null || json.isEmpty()) {
            return null;
        }
        return gson.fromJson(json, VariablesMapping.class);
    }
    
    /**
     * Store last parameters mapping for an address.
     */
    public void storeLastParametersMapping(Address address, ParametersMapping mapping) {
        String key = VARIABLE_PREFIX + "params.last." + address.toString();
        String json = gson.toJson(mapping);
        properties.setString(key, json);
    }
    
    /**
     * Get last parameters mapping for an address.
     */
    public ParametersMapping getLastParametersMapping(Address address) {
        String key = VARIABLE_PREFIX + "params.last." + address.toString();
        String json = properties.getString(key);
        if (json == null || json.isEmpty()) {
            return null;
        }
        return gson.fromJson(json, ParametersMapping.class);
    }
}

