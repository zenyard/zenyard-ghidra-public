package com.zenyard.ghidra.api.exceptions;

/**
 * Base exception for Zenyard API errors.
 */
public class ZenyardApiException extends RuntimeException {
    
    public ZenyardApiException(String message) {
        super(message);
    }
    
    public ZenyardApiException(String message, Throwable cause) {
        super(message, cause);
    }
}

