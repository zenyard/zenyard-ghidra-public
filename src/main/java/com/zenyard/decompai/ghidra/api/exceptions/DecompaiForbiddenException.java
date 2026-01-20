package com.zenyard.decompai.ghidra.api.exceptions;

/**
 * Exception thrown when API returns 403 Forbidden.
 */
public class DecompaiForbiddenException extends DecompaiApiException {
    
    public DecompaiForbiddenException(String message) {
        super(message);
    }
}

