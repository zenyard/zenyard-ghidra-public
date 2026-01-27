package com.zenyard.decompai.ghidra.copilot.tools.models;

/**
 * Represents a memory segment/block.
 */
public class Segment {
    
    private final String name;
    private final String startAddress;
    private final String endAddress;
    private final String permissions; // e.g., "r-x", "rw-"
    private final long length;
    
    public Segment(String name, String startAddress, String endAddress, String permissions, long length) {
        this.name = name;
        this.startAddress = startAddress;
        this.endAddress = endAddress;
        this.permissions = permissions;
        this.length = length;
    }
    
    public String getName() {
        return name;
    }
    
    public String getStartAddress() {
        return startAddress;
    }
    
    public String getEndAddress() {
        return endAddress;
    }
    
    public String getPermissions() {
        return permissions;
    }
    
    public long getLength() {
        return length;
    }
}
