package com.zenyard.decompai.ghidra.copilot.tools.models;

/**
 * Represents a string literal found in the binary.
 */
public class StringData {
    
    private final String address;
    private final String value;
    private final String dataType; // e.g., "string", "unicode"
    private final int length;
    
    public StringData(String address, String value, String dataType, int length) {
        this.address = address;
        this.value = value;
        this.dataType = dataType;
        this.length = length;
    }
    
    public String getAddress() {
        return address;
    }
    
    public String getValue() {
        return value;
    }
    
    public String getDataType() {
        return dataType;
    }
    
    public int getLength() {
        return length;
    }
}
