package com.zenyard.decompai.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import com.zenyard.decompai.ghidra.api.generated.model.SwiftFunction;

/**
 * Tool to get Swift source code for a function.
 * Mirrors get_swift_source in decompai_ida/copilot_tools.py
 */
public class GetSwiftSourceTool {
    
    private final CopilotToolContext context;
    private final Program program;
    
    public GetSwiftSourceTool(CopilotToolContext context) {
        this.context = context;
        this.program = context.getProgram();
    }
    
    @Tool("Returns the decompiled Swift source code of the given function address. " +
          "Throws an error if no Swift source is available for the function.")
    public String getSwiftSource(String address) {
        try {
            context.checkCancelled();
            
            if (program == null) {
                throw new ToolExecutionException("No program is currently loaded");
            }
            
            // Get function at address
            Function function = ToolUtils.getFunction(program, address);
            Address functionAddress = function.getEntryPoint();
            
            // Find SwiftFunction inference
            SwiftFunction swiftFunction = SwiftUtils.findLatestSwiftFunctionInference(program, functionAddress);
            
            if (swiftFunction == null || swiftFunction.getSource() == null || 
                swiftFunction.getSource().isEmpty()) {
                throw new ToolExecutionException(
                    "No Swift source code available for function at " + address);
            }
            
            return swiftFunction.getSource();
            
        } catch (ToolExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new ToolExecutionException(
                "Failed to get Swift source for function at " + address + ": " + e.getMessage(), e);
        }
    }
}

