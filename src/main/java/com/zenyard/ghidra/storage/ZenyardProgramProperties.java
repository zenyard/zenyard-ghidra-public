package com.zenyard.ghidra.storage;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Simple wrapper around Program options for storing plugin data.
 *
 * Uses DomainObject-backed Options to follow save/discard semantics.
 */
public class ZenyardProgramProperties {
    
    private final Program program;
    private final Options options;
    
    public ZenyardProgramProperties(Program program) {
        this.program = program;
        this.options = program.getOptions("Zenyard");
    }
    
    /**
     * Store a string property.
     * In Ghidra, property maps must be created within a transaction.
     */
    public void setString(String key, String value) {
        // Use transaction to ensure property map is created and value is set
        // Note: If we're already in a transaction, startTransaction will return the existing transaction ID
        int transactionId = program.startTransaction("Set Zenyard property: " + key);
        boolean committed = false;
        
        try {
            options.setString(key, value);
            program.endTransaction(transactionId, true);
            committed = true;
        } catch (Exception e) {
            if (!committed) {
                program.endTransaction(transactionId, false);
            }
            Msg.error(this, "Failed to set string property: " + e.getMessage(), e);
        }
    }
    
    /**
     * Get a string property.
     */
    public String getString(String key) {
        return options.getString(key, null);
    }
    
    /**
     * Store an integer property.
     * In Ghidra, property maps must be created within a transaction.
     */
    public void setInt(String key, int value) {
        // Use transaction to ensure property map is created and value is set
        int transactionId = program.startTransaction("Set Zenyard property: " + key);
        boolean committed = false;
        
        try {
            options.setString(key, String.valueOf(value));
            program.endTransaction(transactionId, true);
            committed = true;
        } catch (Exception e) {
            if (!committed) {
                program.endTransaction(transactionId, false);
            }
            Msg.error(this, "Failed to set integer property: " + e.getMessage(), e);
        }
    }
    
    /**
     * Get an integer property.
     */
    public Integer getInt(String key) {
        String cachedValue = options.getString(key, null);
        if (cachedValue != null && !cachedValue.isEmpty()) {
            try {
                return Integer.parseInt(cachedValue);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}

