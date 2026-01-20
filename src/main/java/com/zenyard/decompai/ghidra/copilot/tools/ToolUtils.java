package com.zenyard.decompai.ghidra.copilot.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

/**
 * Utility functions for tool implementations.
 */
public class ToolUtils {
    
    /**
     * Format an address as a hex string (0x...).
     */
    public static String formatAddress(Address address) {
        if (address == null) {
            return null;
        }
        return "0x" + address.toString().replace(":", "");
    }
    
    /**
     * Parse an address from a hex string.
     */
    public static Address parseAddress(Program program, String addressStr) {
        if (program == null || addressStr == null) {
            return null;
        }
        
        // Remove 0x prefix if present
        String cleanAddress = addressStr.startsWith("0x") ? addressStr.substring(2) : addressStr;
        
        try {
            return program.getAddressFactory().getAddress(cleanAddress);
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Get a function by address string.
     */
    public static Function getFunction(Program program, String addressStr) {
        if (program == null || addressStr == null) {
            return null;
        }
        
        Address address = parseAddress(program, addressStr);
        if (address == null) {
            return null;
        }
        
        FunctionManager functionManager = program.getFunctionManager();
        return functionManager.getFunctionAt(address);
    }
    
    /**
     * Get a function containing the given address.
     */
    public static Function getFunctionContaining(Program program, String addressStr) {
        if (program == null || addressStr == null) {
            return null;
        }
        
        Address address = parseAddress(program, addressStr);
        if (address == null) {
            return null;
        }
        
        FunctionManager functionManager = program.getFunctionManager();
        return functionManager.getFunctionContaining(address);
    }
}

