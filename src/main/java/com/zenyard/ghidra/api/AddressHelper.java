package com.zenyard.ghidra.api;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Helper utility for converting between Ghidra Address objects and API address strings.
 * API addresses are represented as 16-character lowercase hexadecimal strings.
 */
public class AddressHelper {

    private static final int API_ADDRESS_HEX_LENGTH = 16;
    
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

    /**
     * Parse a canonical API address key (16 hex digits) into the program default address space.
     *
     * @param program the program (must not be null when key is valid)
     * @param apiAddressKey 16-character hexadecimal string from {@link #fromAddress(Address)}
     * @return the address, or null if {@code program} is null, {@code apiAddressKey} is null/blank,
     *         not exactly 16 hex characters, or parsing fails
     */
    public static Address fromApiAddressKey(Program program, String apiAddressKey) {
        if (program == null || apiAddressKey == null) {
            return null;
        }
        String key = apiAddressKey.trim();
        if (key.length() != API_ADDRESS_HEX_LENGTH || !key.matches("[0-9a-fA-F]+")) {
            return null;
        }
        try {
            long offset = Long.parseUnsignedLong(key, 16);
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (Exception e) {
            return null;
        }
    }
}

