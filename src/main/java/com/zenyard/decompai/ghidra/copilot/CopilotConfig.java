package com.zenyard.decompai.ghidra.copilot;

import java.util.Map;

/**
 * Configuration model for Copilot LLM integration.
 * Mirrors CopilotConfig from the API.
 */
public class CopilotConfig {
    
    private final String modelName;
    private final String modelProvider;
    private final Map<String, Object> additionalParams;
    
    public CopilotConfig(String modelName, String modelProvider, Map<String, Object> additionalParams) {
        this.modelName = modelName;
        this.modelProvider = modelProvider;
        this.additionalParams = additionalParams;
    }
    
    public String getModelName() {
        return modelName;
    }
    
    public String getModelProvider() {
        return modelProvider;
    }
    
    public Map<String, Object> getAdditionalParams() {
        return additionalParams;
    }
    
    /**
     * Get a specific additional parameter value.
     */
    @SuppressWarnings("unchecked")
    public <T> T getAdditionalParam(String key, Class<T> type) {
        Object value = additionalParams.get(key);
        if (value == null) {
            return null;
        }
        if (type.isInstance(value)) {
            return (T) value;
        }
        return null;
    }
    
    /**
     * Get a specific additional parameter value with default.
     */
    @SuppressWarnings("unchecked")
    public <T> T getAdditionalParam(String key, Class<T> type, T defaultValue) {
        T value = getAdditionalParam(key, type);
        return value != null ? value : defaultValue;
    }
}

