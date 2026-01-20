package com.zenyard.decompai.ghidra.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import ghidra.util.Msg;

/**
 * Handles reading, writing, and validation of the configuration file.
 * 
 * NOTE: mirrors decompai_ida/configuration.py functions
 */
public class DecompaiConfigFile {
    
    private static final String CONFIG_FILENAME = "decompai.json";
    private static final Gson GSON = new GsonBuilder()
        .setPrettyPrinting()
        .serializeNulls()
        .create();
    
    /**
     * Get the path to the configuration file.
     * Default location: ~/.ghidra/decompai.json
     * This provides a simple, version-independent location for the configuration.
     */
    public static Path getConfigPath() {
        String userHome = System.getProperty("user.home");
        return Paths.get(userHome, ".ghidra", CONFIG_FILENAME);
    }
    
    /**
     * Read configuration from file.
     * Throws BadConfigurationFileException if file is missing or invalid.
     */
    public static PluginConfiguration readConfiguration() throws BadConfigurationFileException {
        Path configPath = getConfigPath();
        
        if (!Files.exists(configPath)) {
            throw new BadConfigurationFileException(configPath, "Configuration file does not exist");
        }
        
        try {
            String jsonContent = Files.readString(configPath);
            
            // Parse JSON using Gson
            PluginConfiguration config = GSON.fromJson(jsonContent, PluginConfiguration.class);
            
            // Validate required fields
            if (config.getApiUrl() == null || config.getApiUrl().isEmpty()) {
                throw new BadConfigurationFileException(configPath, "api_url is required");
            }
            
            // Log successful read
            Msg.info(DecompaiConfigFile.class, 
                "DecompAI: Configuration loaded from " + configPath);
            
            return config;
        } catch (JsonSyntaxException e) {
            throw new BadConfigurationFileException(configPath, "Invalid JSON format: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            throw new BadConfigurationFileException(configPath, "Invalid configuration: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new BadConfigurationFileException(configPath, "Failed to read configuration file: " + e.getMessage(), e);
        }
    }
    
    /**
     * Write configuration to file.
     */
    public static void writeConfiguration(PluginConfiguration config) throws IOException {
        Path configPath = getConfigPath();
        
        // Create parent directories if needed
        Path parentDir = configPath.getParent();
        if (parentDir != null && !Files.exists(parentDir)) {
            Files.createDirectories(parentDir);
        }
        
        // Serialize to JSON with pretty printing
        String jsonContent = GSON.toJson(config);
        
        // Write to file
        Files.writeString(configPath, jsonContent);
    }
    
    /**
     * Update specific configuration fields without full rewrite.
     * Reads current config, applies updates, writes back.
     */
    public static void updateConfiguration(Map<String, Object> updates) 
            throws BadConfigurationFileException, IOException {
        // Read current configuration (or use defaults if file doesn't exist)
        PluginConfiguration current;
        try {
            current = readConfiguration();
        } catch (BadConfigurationFileException e) {
            // If file doesn't exist, use defaults
            if (!configFileExists()) {
                current = PluginConfiguration.getDefault();
            } else {
                throw e; // Re-throw if file exists but is invalid
            }
        }
        
        // Apply updates
        PluginConfiguration updated = current.withUpdates(updates);
        
        // Write updated configuration
        writeConfiguration(updated);
    }
    
    /**
     * Check if configuration file exists.
     */
    public static boolean configFileExists() {
        return Files.exists(getConfigPath());
    }
}

