package com.zenyard.decompai.ghidra.copilot.tools.models;

/**
 * Represents a local type definition.
 * Mirrors the LocalType dataclass from IDA implementation.
 */
public class LocalType {
    
    private final String name;
    private final String definition;
    
    public LocalType(String name, String definition) {
        this.name = name;
        this.definition = definition;
    }
    
    public String getName() {
        return name;
    }
    
    public String getDefinition() {
        return definition;
    }
}

