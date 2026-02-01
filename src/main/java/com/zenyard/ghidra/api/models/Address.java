package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Represents a 64-bit address as a 16-character lowercase hexadecimal string.
 * 
 * NOTE: mirrors models.address.Address in zenyard/src/models/address.py
 */
public class Address {
    @SerializedName("root")
    private String root;
    
    public Address() {
        // Default constructor for Gson
    }
    
    public Address(String root) {
        if (root == null || !root.matches("^[0-9a-f]{16}$")) {
            throw new IllegalArgumentException("Address must be a 16-character lowercase hexadecimal string");
        }
        this.root = root;
    }
    
    /**
     * Create an Address from an integer value.
     */
    public static Address fromInt(long value) {
        if (value < 0 || value > 0xFFFF_FFFF_FFFF_FFFFL) {
            throw new IllegalArgumentException("Integer out of 64-bit range");
        }
        return new Address(String.format("%016x", value));
    }
    
    /**
     * Convert address to integer.
     */
    public long asInt() {
        return Long.parseLong(root, 16);
    }
    
    public String getRoot() {
        return root;
    }
    
    public void setRoot(String root) {
        this.root = root;
    }
    
    @Override
    public String toString() {
        return root;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Address address = (Address) o;
        return root != null ? root.equals(address.root) : address.root == null;
    }
    
    @Override
    public int hashCode() {
        return root != null ? root.hashCode() : 0;
    }
}

