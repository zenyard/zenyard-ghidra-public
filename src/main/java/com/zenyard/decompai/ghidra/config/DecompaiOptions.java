package com.zenyard.decompai.ghidra.config;

import java.io.IOException;
import java.util.Map;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

/**
 * Manages DecompAI plugin options using configuration file as source of truth.
 * 
 * NOTE: mirrors logic in decompai_ida/configuration.py; candidate for future shared configuration.
 * 
 * Configuration is read from decompai.json file. The UI dialog edits the file directly.
 */
public class DecompaiOptions {
    
    private PluginConfiguration config;
    private final PluginTool tool;
    
    public DecompaiOptions(PluginTool tool) {
        this.tool = tool;
        loadConfiguration();
    }
    
    /**
     * Load configuration from file.
     * Uses defaults if file is missing/invalid.
     * Attempts migration from Ghidra Options API if config file doesn't exist.
     */
    private void loadConfiguration() {
        // Log the expected configuration file path for debugging
        java.nio.file.Path expectedPath = DecompaiConfigFile.getConfigPath();
        Msg.info(this, "DecompAI: Looking for configuration file at: " + expectedPath);
        
        try {
            this.config = DecompaiConfigFile.readConfiguration();
            // Success message is logged in DecompaiConfigFile.readConfiguration()
        } catch (BadConfigurationFileException e) {
            // Show warning dialog if file exists but is invalid
            if (DecompaiConfigFile.configFileExists()) {
                java.awt.Component parent = (tool != null) ? tool.getActiveWindow() : null;
                Msg.showWarn(this, parent, 
                    "Configuration File Error: Could not read decompai.json: " + e.getMessage() +
                    "\nUsing default configuration.\n\nFile location: " + e.getConfigPath() +
                    "\n\nYou can edit the file manually or use Tools → DecompAI → Configuration...", e);
            } else {
                // File doesn't exist - try migration from Options API, then use defaults
                if (migrateFromOptionsApi()) {
                    // Migration successful, reload from file
                    try {
                        this.config = DecompaiConfigFile.readConfiguration();
                        Msg.info(this, "DecompAI: Migrated configuration from Ghidra Options to decompai.json");
                        return;
                    } catch (BadConfigurationFileException ex) {
                        // Should not happen, but fall through to defaults
                    }
                }
                // Use defaults silently (user can configure via dialog)
                Msg.info(this, "DecompAI: Configuration file not found. Using defaults. " +
                    "Configure via Tools → DecompAI → Configuration...");
            }
            this.config = PluginConfiguration.getDefault();
        }
    }
    
    /**
     * Migrate configuration from Ghidra Options API to config file.
     * Returns true if migration was performed.
     */
    private boolean migrateFromOptionsApi() {
        try {
            // Check if we have values in Options API (from previous version)
            ghidra.framework.options.Options oldOptions = tool.getOptions("DecompAI");
            
            String apiKey = oldOptions.getString("API Key", "");
            String serverUrl = oldOptions.getString("Server URL", "");
            boolean showInitialUploadMessage = oldOptions.getBoolean("Show Initial Upload Message", true);
            boolean requestBinaryInstructions = oldOptions.getBoolean("Request Binary Instructions", false);
            String logLevel = oldOptions.getString("Log Level", "INFO");
            
            // If we have an API key in Options, migrate it
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                // Create config from Options values
                PluginConfiguration migratedConfig = new PluginConfiguration(
                    serverUrl.isEmpty() ? PluginConfiguration.getDefault().getApiUrl() : serverUrl,
                    apiKey,
                    logLevel,
                    showInitialUploadMessage,
                    requestBinaryInstructions,
                    true, // require_confirmation_per_db (default)
                    true  // verify_ssl (default)
                );
                
                // Write to config file
                DecompaiConfigFile.writeConfiguration(migratedConfig);
                return true;
            }
        } catch (Exception e) {
            // Migration failed - ignore and use defaults
            Msg.debug(this, "Failed to migrate from Options API: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * Reload configuration from file.
     * Useful after external edits or after dialog saves.
     */
    public void reloadConfiguration() {
        loadConfiguration();
    }
    
    /**
     * Get the underlying PluginConfiguration object.
     */
    public PluginConfiguration getConfiguration() {
        return config;
    }
    
    // Getters delegate to config object
    public String getApiKey() {
        return config.getApiKey();
    }
    
    public String getServerUrl() {
        return config.getApiUrl();
    }
    
    public boolean isShowInitialUploadMessage() {
        return config.isShowInitialUploadMessage();
    }
    
    public boolean isRequestBinaryInstructions() {
        return config.isRequestBinaryInstructions();
    }
    
    public String getLogLevel() {
        return config.getLogLevel();
    }
    
    public boolean isRequireConfirmationPerDb() {
        return config.isRequireConfirmationPerDb();
    }
    
    public boolean isVerifySsl() {
        return config.isVerifySsl();
    }
    
    public boolean isConfigured() {
        return config.isConfigured();
    }
    
    /**
     * Update configuration (writes to file).
     */
    public void updateConfiguration(Map<String, Object> updates) throws IOException {
        try {
            DecompaiConfigFile.updateConfiguration(updates);
            reloadConfiguration(); // Reload to get updated values
        } catch (BadConfigurationFileException e) {
            throw new IOException("Failed to update configuration: " + e.getMessage(), e);
        }
    }
}

