package com.zenyard.ghidra.api.exceptions;

/**
 * Exception thrown when API returns 403 Forbidden.
 */
public class ZenyardForbiddenException extends ZenyardApiException {
    
    public ZenyardForbiddenException(String message) {
        super(message);
    }
}

