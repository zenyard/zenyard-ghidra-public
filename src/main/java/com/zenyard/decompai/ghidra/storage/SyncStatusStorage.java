package com.zenyard.decompai.ghidra.storage;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

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
    private static final String DIRTY_LIST_KEY = "dirty_addresses";
    private static final Gson gson = new GsonBuilder().create();
    
    private final Program program;
    private final DecompaiProgramProperties properties;
    
    public SyncStatusStorage(Program program) {
        this.program = program;
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

        updateDirtyAddressList(address, status.isDirty());
    }
    
    /**
     * Get all addresses with dirty=true.
     */
    public List<Address> getDirtyAddresses() {
        List<Address> dirtyAddresses = new ArrayList<>();
        
        Set<String> dirtyAddressStrings = getDirtyAddressStrings();
        for (String addressString : dirtyAddressStrings) {
            Address address = program.getAddressFactory().getAddress(addressString);
            if (address != null) {
                dirtyAddresses.add(address);
            } else {
                Msg.warn(this, "Failed to parse dirty address: " + addressString);
            }
        }
        return dirtyAddresses;
    }
    
    /**
     * Check if an address is dirty.
     */
    public boolean isDirty(Address address) {
        Optional<SyncStatus> status = getSyncStatus(address);
        return status.map(SyncStatus::isDirty).orElse(false);
    }
    
    /**
     * Mark an address as dirty.
     */
    public void markDirty(Address address) {
        Optional<SyncStatus> current = getSyncStatus(address);
        SyncStatus updated = current.orElse(new SyncStatus())
            .withDirty(true);
        setSyncStatus(address, updated);
        Msg.info(this, "Marked address " + address + " as dirty");
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

    private Set<String> getDirtyAddressStrings() {
        String json = properties.getString(DIRTY_LIST_KEY);
        if (json == null || json.isEmpty()) {
            return new HashSet<>();
        }

        try {
            String[] addresses = gson.fromJson(json, String[].class);
            if (addresses == null) {
                return new HashSet<>();
            }
            return new HashSet<>(Arrays.asList(addresses));
        } catch (Exception e) {
            Msg.warn(this, "Failed to parse dirty address list: " + e.getMessage());
            return new HashSet<>();
        }
    }

    private void setDirtyAddressStrings(Set<String> addresses) {
        String json = gson.toJson(addresses);
        properties.setString(DIRTY_LIST_KEY, json);
    }

    private void updateDirtyAddressList(Address address, boolean dirty) {
        if (address == null) {
            return;
        }

        Set<String> dirtyAddresses = getDirtyAddressStrings();
        String addressString = address.toString();
        if (dirty) {
            dirtyAddresses.add(addressString);
        } else {
            dirtyAddresses.remove(addressString);
        }
        setDirtyAddressStrings(dirtyAddresses);
    }
    
    /**
     * Internal data class for JSON serialization.
     */
    private static class SyncStatusData {
        String uploadedHash;
        boolean dirty;
    }
}

