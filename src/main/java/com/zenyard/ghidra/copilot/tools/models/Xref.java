package com.zenyard.ghidra.copilot.tools.models;

/**
 * Represents a cross-reference (xref) to or from an address.
 */
public class Xref {
    
    private final String fromAddress;
    private final String toAddress;
    private final String referenceType;
    private final String context; // e.g., function name where reference occurs
    
    public Xref(String fromAddress, String toAddress, String referenceType, String context) {
        this.fromAddress = fromAddress;
        this.toAddress = toAddress;
        this.referenceType = referenceType;
        this.context = context;
    }
    
    public String getFromAddress() {
        return fromAddress;
    }
    
    public String getToAddress() {
        return toAddress;
    }
    
    public String getReferenceType() {
        return referenceType;
    }
    
    public String getContext() {
        return context;
    }
}
