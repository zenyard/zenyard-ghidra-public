package com.zenyard.ghidra.copilot.tools.models;

import ghidra.program.model.listing.Program;

import com.zenyard.ghidra.copilot.tools.SwiftUtils;
import com.zenyard.ghidra.copilot.tools.ToolUtils;

/**
 * Represents a function in the binary.
 * Mirrors the Function dataclass from IDA implementation.
 */
public class Function {
    
    private final String name;
    private final String address;
    private final boolean swiftSourceAvailable;
    
    public Function(String name, String address, boolean swiftSourceAvailable) {
        this.name = name;
        this.address = address;
        this.swiftSourceAvailable = swiftSourceAvailable;
    }
    
    public String getName() {
        return name;
    }
    
    public String getAddress() {
        return address;
    }
    
    public boolean isSwiftSourceAvailable() {
        return swiftSourceAvailable;
    }
    
    /**
     * Create a Function from a Ghidra Function.
     * Checks if Swift source is available for the function.
     */
    public static Function fromGhidraFunction(ghidra.program.model.listing.Function ghidraFunction) {
        return fromGhidraFunction(ghidraFunction, null);
    }
    
    /**
     * Create a Function from a Ghidra Function with program context for Swift detection.
     */
    public static Function fromGhidraFunction(ghidra.program.model.listing.Function ghidraFunction, Program program) {
        String name = ghidraFunction.getName();
        String address = ToolUtils.formatAddress(ghidraFunction.getEntryPoint());
        boolean swiftSourceAvailable = false;
        
        if (program != null) {
            swiftSourceAvailable = SwiftUtils.hasSwiftSource(program, ghidraFunction.getEntryPoint());
        }
        
        return new Function(name, address, swiftSourceAvailable);
    }
}

