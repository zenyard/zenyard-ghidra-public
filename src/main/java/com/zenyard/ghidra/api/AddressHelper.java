package com.zenyard.ghidra.api;

import ghidra.program.model.address.Address;

/**
 * Helper utility for converting between Ghidra Address objects and API address strings.
 * API addresses are represented as 16-character lowercase hexadecimal strings.
 */
public class AddressHelper {
    
    /**
     * Convert a Ghidra Address to an API address string (16-character hex).
     * 
     * @param address The Ghidra address
     * @return 16-character lowercase hexadecimal string representation
     */
    public static String fromAddress(Address address) {
        if (address == null) {
            return null;
        }
        long offset = address.getOffset();
        // Note: Java's long is signed, but String.format("%016x", offset) correctly formats
        // any long value (including negative ones) as a 16-character hex string representing
        // the unsigned 64-bit value. No validation needed - all long values are valid.
        return String.format("%016x", offset);
    }
    
    /**
     * Convert a long offset to an API address string (16-character hex).
     * 
     * @param offset The address offset
     * @return 16-character lowercase hexadecimal string representation
     */
    public static String fromLong(long offset) {
        // Note: Java's long is signed, but String.format("%016x", offset) correctly formats
        // any long value (including negative ones) as a 16-character hex string representing
        // the unsigned 64-bit value. No validation needed - all long values are valid.
        return String.format("%016x", offset);
    }
}

