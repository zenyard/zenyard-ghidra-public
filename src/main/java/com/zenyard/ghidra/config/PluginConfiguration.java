 package com.zenyard.ghidra.config;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import com.google.gson.annotations.SerializedName;

/**
 * Immutable configuration class matching IDA plugin's PluginConfiguration.
 * 
 * NOTE: mirrors zenyard_ida/configuration.py PluginConfiguration
 */
public class PluginConfiguration {
    
    @SerializedName("api_url")
    private final String apiUrl;
    
    @SerializedName("api_key")
    private final String apiKey;
    
    @SerializedName("log_level")
    private final String logLevel;
    
    @SerializedName("show_initial_upload_message")
    private final Boolean showInitialUploadMessage;
    
    @SerializedName("request_binary_instructions")
    private final Boolean requestBinaryInstructions;
    
    @SerializedName("require_confirmation_per_db")
    private final Boolean requireConfirmationPerDb;
    
    @SerializedName("verify_ssl")
    private final Boolean verifySsl;

    @SerializedName("accepted_eula_version")
    private final Integer acceptedEulaVersion;
    
    // Default values matching IDA plugin
    private static final String DEFAULT_SERVER_URL = "https://api.zenyard.ai";
    private static final String DEFAULT_LOG_LEVEL = "INFO";
    private static final boolean DEFAULT_SHOW_INITIAL_UPLOAD_MESSAGE = true;
    private static final boolean DEFAULT_REQUEST_BINARY_INSTRUCTIONS = true;
    private static final boolean DEFAULT_REQUIRE_CONFIRMATION_PER_DB = true;
    private static final boolean DEFAULT_VERIFY_SSL = true;
    private static final int DEFAULT_ACCEPTED_EULA_VERSION = 0;
    
    // Constructor for Gson deserialization
    // Note: @SerializedName annotations are on fields, not constructor parameters
    public PluginConfiguration(
            String apiUrl,
            String apiKey,
            String logLevel,
            Boolean showInitialUploadMessage,
            Boolean requestBinaryInstructions,
            Boolean requireConfirmationPerDb,
            Boolean verifySsl,
            Integer acceptedEulaVersion) {
        this.apiUrl = apiUrl != null ? apiUrl : DEFAULT_SERVER_URL;
        this.apiKey = apiKey != null ? apiKey : "";
        this.logLevel = logLevel != null ? logLevel : DEFAULT_LOG_LEVEL;
        this.showInitialUploadMessage = showInitialUploadMessage != null ? showInitialUploadMessage : DEFAULT_SHOW_INITIAL_UPLOAD_MESSAGE;
        this.requestBinaryInstructions = requestBinaryInstructions != null ? requestBinaryInstructions : DEFAULT_REQUEST_BINARY_INSTRUCTIONS;
        this.requireConfirmationPerDb = requireConfirmationPerDb != null ? requireConfirmationPerDb : DEFAULT_REQUIRE_CONFIRMATION_PER_DB;
        this.verifySsl = verifySsl != null ? verifySsl : DEFAULT_VERIFY_SSL;
        this.acceptedEulaVersion = acceptedEulaVersion != null ? acceptedEulaVersion : DEFAULT_ACCEPTED_EULA_VERSION;
        
        validate();
    }
    
    /**
     * Create default configuration.
     */
    public static PluginConfiguration getDefault() {
        return new PluginConfiguration(
            DEFAULT_SERVER_URL,
            "",
            DEFAULT_LOG_LEVEL,
            DEFAULT_SHOW_INITIAL_UPLOAD_MESSAGE,
            DEFAULT_REQUEST_BINARY_INSTRUCTIONS,
            DEFAULT_REQUIRE_CONFIRMATION_PER_DB,
            DEFAULT_VERIFY_SSL,
            DEFAULT_ACCEPTED_EULA_VERSION
        );
    }
    
    /**
     * Create a new configuration with updated user-editable fields.
     * Preserves other fields (matching IDA's with_user_config pattern).
     */
    public PluginConfiguration withUserConfig(String apiUrl, String apiKey) {
        return new PluginConfiguration(
            apiUrl,
            apiKey,
            this.logLevel,
            this.showInitialUploadMessage,
            this.requestBinaryInstructions,
            this.requireConfirmationPerDb,
            this.verifySsl,
            this.acceptedEulaVersion
        );
    }
    
    /**
     * Create a copy with updated fields.
     */
    public PluginConfiguration withUpdates(Map<String, Object> updates) {
        String newApiUrl = updates.containsKey("api_url") ? (String) updates.get("api_url") : this.apiUrl;
        String newApiKey = updates.containsKey("api_key") ? (String) updates.get("api_key") : this.apiKey;
        String newLogLevel = updates.containsKey("log_level") ? (String) updates.get("log_level") : this.logLevel;
        Boolean newShowInitialUploadMessage = updates.containsKey("show_initial_upload_message") 
            ? (Boolean) updates.get("show_initial_upload_message") : this.showInitialUploadMessage;
        Boolean newRequestBinaryInstructions = updates.containsKey("request_binary_instructions")
            ? (Boolean) updates.get("request_binary_instructions") : this.requestBinaryInstructions;
        Boolean newRequireConfirmationPerDb = updates.containsKey("require_confirmation_per_db")
            ? (Boolean) updates.get("require_confirmation_per_db") : this.requireConfirmationPerDb;
        Boolean newVerifySsl = updates.containsKey("verify_ssl")
            ? (Boolean) updates.get("verify_ssl") : this.verifySsl;
        Integer newAcceptedEulaVersion = this.acceptedEulaVersion;
        if (updates.containsKey("accepted_eula_version")) {
            Object value = updates.get("accepted_eula_version");
            if (value instanceof Number) {
                newAcceptedEulaVersion = ((Number) value).intValue();
            } else if (value instanceof String) {
                try {
                    newAcceptedEulaVersion = Integer.parseInt((String) value);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid accepted_eula_version: " + value);
                }
            } else if (value == null) {
                newAcceptedEulaVersion = DEFAULT_ACCEPTED_EULA_VERSION;
            }
        }
        
        return new PluginConfiguration(
            newApiUrl,
            newApiKey,
            newLogLevel,
            newShowInitialUploadMessage,
            newRequestBinaryInstructions,
            newRequireConfirmationPerDb,
            newVerifySsl,
            newAcceptedEulaVersion
        );
    }
    
    /**
     * Validate configuration.
     */
    private void validate() {
        // Validate URL format
        if (apiUrl != null && !apiUrl.isEmpty()) {
            try {
                new URL(apiUrl);
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException("Invalid api_url format: " + apiUrl, e);
            }
        }
        
        // Validate log level
        if (logLevel != null) {
            String upperLevel = logLevel.toUpperCase();
            if (!upperLevel.equals("DEBUG") && !upperLevel.equals("INFO") 
                && !upperLevel.equals("WARN") && !upperLevel.equals("WARNING") 
                && !upperLevel.equals("ERROR") && !upperLevel.equals("CRITICAL") 
                && !upperLevel.equals("FATAL")) {
                throw new IllegalArgumentException("Invalid log_level: " + logLevel);
            }
        }
        
        // Validate API key (must not be empty if provided)
        // Note: Empty is allowed for initial setup, but isConfigured() will return false
    }
    
    // Getters
    public String getApiUrl() {
        return apiUrl;
    }
    
    public String getApiKey() {
        return apiKey;
    }
    
    public String getLogLevel() {
        return logLevel;
    }
    
    public boolean isShowInitialUploadMessage() {
        return showInitialUploadMessage;
    }
    
    public boolean isRequestBinaryInstructions() {
        return requestBinaryInstructions;
    }
    
    public boolean isRequireConfirmationPerDb() {
        return requireConfirmationPerDb;
    }
    
    public boolean isVerifySsl() {
        return verifySsl;
    }

    public int getAcceptedEulaVersion() {
        return acceptedEulaVersion != null ? acceptedEulaVersion : DEFAULT_ACCEPTED_EULA_VERSION;
    }
    
    public boolean isConfigured() {
        return apiKey != null && !apiKey.trim().isEmpty();
    }
}

