package com.zenyard.decompai.ghidra.storage;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Storage for sync status per address.
 * 
 * Stores SyncStatus objects as JSON in program properties.
 * Key pattern: sync_status.<address>
 */
public class SyncStatusStorage {
    private static final String PROPERTY_PREFIX = "sync_status.";
    private static final Gson gson = new GsonBuilder().create();
    
    private final DecompaiProgramProperties properties;
    
    public SyncStatusStorage(Program program) {
        this.properties = new DecompaiProgramProperties(program);
    }
    
    /**
     * Get sync status for an address.
     */
    public Optional<SyncStatus> getSyncStatus(Address address) {
        String key = PROPERTY_PREFIX + address.toString();
        String json = properties.getString(key);
        
        if (json == null || json.isEmpty()) {
            return Optional.empty();
        }
        
        try {
            SyncStatusData data = gson.fromJson(json, SyncStatusData.class);
            Optional<String> hash = data.uploadedHash != null && !data.uploadedHash.isEmpty() 
                ? Optional.of(data.uploadedHash) 
                : Optional.empty();
            return Optional.of(new SyncStatus(hash, data.dirty));
        } catch (Exception e) {
            Msg.warn(this, "Failed to parse sync status for " + address + ": " + e.getMessage());
            return Optional.empty();
        }
    }
    
    /**
     * Set sync status for an address.
     */
    public void setSyncStatus(Address address, SyncStatus status) {
        String key = PROPERTY_PREFIX + address.toString();
        SyncStatusData data = new SyncStatusData();
        data.uploadedHash = status.getUploadedHash().orElse(null);
        data.dirty = status.isDirty();
        
        String json = gson.toJson(data);
        properties.setString(key, json);
    }
    
    /**
     * Get all addresses with dirty=true.
     */
    public List<Address> getDirtyAddresses() {
        List<Address> dirtyAddresses = new ArrayList<>();
        
        // We need to iterate through all possible addresses or maintain a separate list
        // For now, we'll use a simpler approach: check all functions and global variables
        // This will be optimized when we integrate with ObjectReader
        // For now, return empty list - will be populated by TrackChangesTask
        return dirtyAddresses;
    }
    
    /**
     * Check if an address is dirty.
     */
    public boolean isDirty(Address address) {
        Optional<SyncStatus> status = getSyncStatus(address);
        return status.map(SyncStatus::isDirty).orElse(true); // Default to dirty if not found
    }
    
    /**
     * Mark an address as dirty.
     */
    public void markDirty(Address address) {
        Optional<SyncStatus> current = getSyncStatus(address);
        SyncStatus updated = current.orElse(new SyncStatus())
            .withDirty(true);
        setSyncStatus(address, updated);
    }
    
    /**
     * Mark an address as clean.
     */
    public void markClean(Address address) {
        Optional<SyncStatus> current = getSyncStatus(address);
        SyncStatus updated = current.orElse(new SyncStatus())
            .withDirty(false);
        setSyncStatus(address, updated);
    }
    
    /**
     * Internal data class for JSON serialization.
     */
    private static class SyncStatusData {
        String uploadedHash;
        boolean dirty;
    }
}

