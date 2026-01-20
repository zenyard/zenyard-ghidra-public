package com.zenyard.decompai.ghidra.api.exceptions;

/**
 * Exception thrown when API returns 401 Unauthorized.
 */
public class DecompaiUnauthorizedException extends DecompaiApiException {
    
    public DecompaiUnauthorizedException(String message) {
        super(message);
    }
}

