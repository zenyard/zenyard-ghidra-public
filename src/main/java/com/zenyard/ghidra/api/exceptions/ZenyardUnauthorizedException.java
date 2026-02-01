package com.zenyard.ghidra.api.exceptions;

/**
 * Exception thrown when API returns 401 Unauthorized.
 */
public class ZenyardUnauthorizedException extends ZenyardApiException {
    
    public ZenyardUnauthorizedException(String message) {
        super(message);
    }
}

