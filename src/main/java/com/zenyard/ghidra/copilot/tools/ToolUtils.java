package com.zenyard.ghidra.copilot.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import java.util.Map;
import java.util.function.Supplier;

import com.zenyard.ghidra.copilot.storage.CopilotArtifactStorage;
import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

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

    /**
     * Execute a tool action with optional execution hooks.
     */
    public static <T> T executeTool(
            CopilotToolContext context,
            String toolName,
            Map<String, Object> arguments,
            Supplier<T> action) {
        ToolExecutionListener listener = context != null ? context.getToolExecutionListener() : null;
        long startTime = System.nanoTime();
        if (listener != null) {
            listener.onToolStart(toolName, arguments);
        }
        try {
            T result = action.get();
            if (listener != null) {
                listener.onToolSuccess(toolName, elapsedMs(startTime));
            }
            return result;
        } catch (RuntimeException e) {
            if (listener != null) {
                listener.onToolError(toolName, e, elapsedMs(startTime));
            }
            throw e;
        } catch (Exception e) {
            if (listener != null) {
                listener.onToolError(toolName, e, elapsedMs(startTime));
            }
            throw new ToolExecutionException("Tool execution failed: " + e.getMessage(), e);
        }
    }

    public static ToolOutput persistLargeOutput(
            CopilotToolContext context,
            String artifactBaseName,
            String content,
            Integer itemCount) {
        String inlineContent = null;
        if (content != null && content.length() <= 4000) {
            inlineContent = content;
        }
        CopilotArtifactStorage storage = context != null ? context.getArtifactStorage() : null;
        if (storage == null) {
            return new ToolOutput(
                "Large output generated (no artifact storage available)",
                null,
                itemCount,
                inlineContent);
        }
        String artifactPath = "tools/" + artifactBaseName + "-" + System.currentTimeMillis() + ".txt";
        storage.writeArtifacts(Map.of(artifactPath, content != null ? content : ""));
        String summary = "Stored output in artifact: " + artifactPath;
        return new ToolOutput(summary, artifactPath, itemCount, inlineContent);
    }

    private static long elapsedMs(long startTimeNs) {
        return (System.nanoTime() - startTimeNs) / 1_000_000L;
    }
}

