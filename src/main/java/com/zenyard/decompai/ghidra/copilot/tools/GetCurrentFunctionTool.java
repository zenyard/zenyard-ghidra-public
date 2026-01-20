package com.zenyard.decompai.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

import com.zenyard.decompai.ghidra.copilot.tools.models.Function;

/**
 * Tool to get the current function at the cursor.
 */
public class GetCurrentFunctionTool {
    
    private final CopilotToolContext context;
    private final PluginTool tool;
    
    public GetCurrentFunctionTool(CopilotToolContext context, PluginTool tool) {
        this.context = context;
        this.tool = tool;
    }
    
    @Tool("Returns the current function address and name, or null if not currently in a function")
    public Function getCurrentFunction() {
        try {
            context.checkCancelled();
            
            Program program = context.getProgram();
            if (program == null) {
                throw new ToolExecutionException("No program is currently loaded");
            }
            
            // Get current address from tool using LocationProvider
            Address currentAddress = com.zenyard.decompai.ghidra.util.GhidraProgramUtils.getCurrentAddress(tool);
            
            if (currentAddress == null) {
                return null;
            }
            
            FunctionManager functionManager = program.getFunctionManager();
            ghidra.program.model.listing.Function function = functionManager.getFunctionContaining(currentAddress);
            
            if (function == null) {
                return null;
            }
            
            // Check if Swift source is available using SwiftUtils
            boolean swiftSourceAvailable = SwiftUtils.hasSwiftSource(program, function.getEntryPoint());
            
            return new Function(
                function.getName(),
                ToolUtils.formatAddress(function.getEntryPoint()),
                swiftSourceAvailable
            );
        } catch (ToolExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new ToolExecutionException("Failed to get current function: " + e.getMessage(), e);
        }
    }
}

