package com.zenyard.ghidra.storage;

import java.util.Objects;
import java.util.Optional;

/**
 * Sync status for an object address.
 * 
 * Mirrors zenyard_ida/model.py SyncStatus class.
 * Tracks whether an object has been uploaded and if it's dirty (changed).
 */
public class SyncStatus {
    private final Optional<String> uploadedHash; // base64-encoded BLAKE2b hash (8 bytes)
    private final boolean dirty;
    
    public SyncStatus() {
        this.uploadedHash = Optional.empty();
        this.dirty = true;
    }
    
    public SyncStatus(Optional<String> uploadedHash, boolean dirty) {
        this.uploadedHash = uploadedHash;
        this.dirty = dirty;
    }
    
    public Optional<String> getUploadedHash() {
        return uploadedHash;
    }
    
    public boolean isDirty() {
        return dirty;
    }
    
    /**
     * Create a new SyncStatus with updated dirty flag.
     */
    public SyncStatus withDirty(boolean dirty) {
        return new SyncStatus(this.uploadedHash, dirty);
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SyncStatus that = (SyncStatus) o;
        return dirty == that.dirty && Objects.equals(uploadedHash, that.uploadedHash);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(uploadedHash, dirty);
    }
    
    @Override
    public String toString() {
        return "SyncStatus{uploadedHash=" + uploadedHash + ", dirty=" + dirty + "}";
    }
}

