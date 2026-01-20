package com.zenyard.decompai.ghidra.api.exceptions;

/**
 * Base exception for DecompAI API errors.
 */
public class DecompaiApiException extends RuntimeException {
    
    public DecompaiApiException(String message) {
        super(message);
    }
    
    public DecompaiApiException(String message, Throwable cause) {
        super(message, cause);
    }
}

