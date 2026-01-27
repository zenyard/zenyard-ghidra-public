package com.zenyard.decompai.ghidra.copilot.tools.models;

/**
 * Comprehensive information about an address in the program.
 */
public class AddressDetails {
    
    private final String address;
    private final String addressType; // "function", "data", "code", "unknown"
    private final String label; // Symbol name if any
    private final String dataType; // Data type if it's data
    private final String functionName; // Function name if in a function
    private final String comment; // Comment at this address
    private final String value; // Value representation if data
    
    public AddressDetails(String address, String addressType, String label, String dataType, 
                         String functionName, String comment, String value) {
        this.address = address;
        this.addressType = addressType;
        this.label = label;
        this.dataType = dataType;
        this.functionName = functionName;
        this.comment = comment;
        this.value = value;
    }
    
    public String getAddress() {
        return address;
    }
    
    public String getAddressType() {
        return addressType;
    }
    
    public String getLabel() {
        return label;
    }
    
    public String getDataType() {
        return dataType;
    }
    
    public String getFunctionName() {
        return functionName;
    }
    
    public String getComment() {
        return comment;
    }
    
    public String getValue() {
        return value;
    }
}
