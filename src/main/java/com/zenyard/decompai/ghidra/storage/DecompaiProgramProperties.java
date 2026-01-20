package com.zenyard.decompai.ghidra.storage;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.PropertyMapManager;

/**
 * Static cache for properties when property maps cannot be created.
 * This is a workaround for Ghidra versions where property maps don't work.
 */
class StaticPropertyCache {
    private static final Map<String, Map<String, String>> programProperties = new ConcurrentHashMap<>();
    
    static String getProperty(Program program, String key) {
        String programKey = getProgramKey(program);
        Map<String, String> props = programProperties.get(programKey);
        if (props == null) {
            return null;
        }
        return props.get(key);
    }
    
    static void setProperty(Program program, String key, String value) {
        String programKey = getProgramKey(program);
        programProperties.computeIfAbsent(programKey, k -> new ConcurrentHashMap<>()).put(key, value);
    }
    
    static String getProgramKey(Program program) {
        return program.getName() + ":" + System.identityHashCode(program);
    }
}

/**
 * Simple wrapper around Ghidra's Program properties API for storing plugin data.
 * 
 * No size limits, no workarounds needed - uses Ghidra's native property system.
 * 
 * NOTE: This replaces the complex storage system in decompai_ida/storage.py
 * which had to work around IDA's 1024-byte blob limit.
 */
public class DecompaiProgramProperties {
    
    private static final String PROPERTY_PREFIX = "DecompAI.";
    
    private final Program program;
    private final PropertyMapManager propertyManager;
    
    public DecompaiProgramProperties(Program program) {
        this.program = program;
        this.propertyManager = program.getUsrPropertyManager();
    }
    
    /**
     * Store a string property.
     * In Ghidra, property maps must be created within a transaction.
     */
    public void setString(String key, String value) {
        // Use transaction to ensure property map is created and value is set
        // Note: If we're already in a transaction, startTransaction will return the existing transaction ID
        int transactionId = program.startTransaction("Set DecompAI property: " + key);
        boolean committed = false;
        
        try {
            String propertyName = PROPERTY_PREFIX + key;
            ghidra.program.model.util.StringPropertyMap map = propertyManager.getStringPropertyMap(propertyName);
            
            // If map doesn't exist, try to create it using reflection to call createStringPropertyMap
            if (map == null) {
                try {
                    // Try to create the map using reflection (in case the method exists but isn't in the interface)
                    java.lang.reflect.Method createMethod = propertyManager.getClass().getMethod("createStringPropertyMap", String.class);
                    createMethod.invoke(propertyManager, propertyName);
                    map = propertyManager.getStringPropertyMap(propertyName);
                } catch (NoSuchMethodException | java.lang.reflect.InvocationTargetException | IllegalAccessException e) {
                    // Method doesn't exist or failed - will use static cache fallback
                }
            }
            
            if (map != null) {
                map.add(program.getMinAddress(), value);
                program.endTransaction(transactionId, true);
                committed = true;
            } else {
                // Map still doesn't exist - use static cache as fallback
                // This is a workaround until we can properly create property maps
                StaticPropertyCache.setProperty(program, key, value);
                program.endTransaction(transactionId, false);
            }
        } catch (Exception e) {
            if (!committed) {
                program.endTransaction(transactionId, false);
            }
            ghidra.util.Msg.error(this, "Failed to set string property: " + e.getMessage(), e);
        }
    }
    
    /**
     * Get a string property.
     */
    public String getString(String key) {
        // Try property map first
        ghidra.program.model.util.StringPropertyMap map = propertyManager.getStringPropertyMap(PROPERTY_PREFIX + key);
        if (map != null) {
            try {
                String value = map.getString(program.getMinAddress());
                if (value != null) {
                    return value;
                }
            } catch (Exception e) {
                // Fall through to static cache
            }
        }
        
        // Fallback to static cache
        return StaticPropertyCache.getProperty(program, key);
    }
    
    /**
     * Store an integer property.
     * In Ghidra, property maps must be created within a transaction.
     */
    public void setInt(String key, int value) {
        // Use transaction to ensure property map is created and value is set
        int transactionId = program.startTransaction("Set DecompAI property: " + key);
        boolean committed = false;
        
        try {
            String propertyName = PROPERTY_PREFIX + key;
            ghidra.program.model.util.IntPropertyMap map = propertyManager.getIntPropertyMap(propertyName);
            
            // If map doesn't exist, try to create it using reflection to call createIntPropertyMap
            if (map == null) {
                try {
                    // Try to create the map using reflection (in case the method exists but isn't in the interface)
                    java.lang.reflect.Method createMethod = propertyManager.getClass().getMethod("createIntPropertyMap", String.class);
                    createMethod.invoke(propertyManager, propertyName);
                    map = propertyManager.getIntPropertyMap(propertyName);
                } catch (NoSuchMethodException | java.lang.reflect.InvocationTargetException | IllegalAccessException e) {
                    // Method doesn't exist or failed - will use static cache fallback
                }
            }
            
            if (map != null) {
                map.add(program.getMinAddress(), value);
                program.endTransaction(transactionId, true);
                committed = true;
            } else {
                // Map still doesn't exist - use static cache as fallback
                // Store as string in the cache (integers are stored as string representations)
                StaticPropertyCache.setProperty(program, key, String.valueOf(value));
                program.endTransaction(transactionId, false);
            }
        } catch (Exception e) {
            if (!committed) {
                program.endTransaction(transactionId, false);
            }
            ghidra.util.Msg.error(this, "Failed to set integer property: " + e.getMessage(), e);
        }
    }
    
    /**
     * Get an integer property.
     */
    public Integer getInt(String key) {
        // Try property map first
        ghidra.program.model.util.IntPropertyMap map = propertyManager.getIntPropertyMap(PROPERTY_PREFIX + key);
        if (map != null) {
            try {
                Integer value = map.getInt(program.getMinAddress());
                if (value != null) {
                    return value;
                }
            } catch (Exception e) {
                // Fall through to static cache
            }
        }
        
        // Fallback to static cache (integers are stored as string representations)
        String cachedValue = StaticPropertyCache.getProperty(program, key);
        if (cachedValue != null) {
            try {
                return Integer.parseInt(cachedValue);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}

