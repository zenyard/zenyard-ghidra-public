package com.zenyard.ghidra.config;

import java.nio.file.Path;

/**
 * Exception thrown when the configuration file is missing or contains invalid data.
 * 
 * NOTE: mirrors zenyard_ida/configuration.py BadConfigurationFile
 */
public class BadConfigurationFileException extends Exception {
    
    private final Path configPath;
    
    public BadConfigurationFileException(Path configPath, String message) {
        super("Bad configuration file at " + configPath + ": " + message);
        this.configPath = configPath;
    }
    
    public BadConfigurationFileException(Path configPath, String message, Throwable cause) {
        super("Bad configuration file at " + configPath + ": " + message, cause);
        this.configPath = configPath;
    }
    
    public Path getConfigPath() {
        return configPath;
    }
}

