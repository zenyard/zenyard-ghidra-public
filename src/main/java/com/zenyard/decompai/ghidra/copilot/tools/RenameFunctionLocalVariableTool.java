package com.zenyard.decompai.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Tool to rename a local variable in a function.
 * 
 * Note: This is a complex operation that requires decompiler API access.
 */
public class RenameFunctionLocalVariableTool {
    
    private final CopilotToolContext context;
    
    public RenameFunctionLocalVariableTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Rename a local variable in the given function")
    public void renameFunctionLocalVariable(String address, String fromName, String toName) {
        try {
            context.checkCancelled();
            
            Program program = context.getProgram();
            if (program == null) {
                throw new ToolExecutionException("No program is currently loaded");
            }
            
            Function function = ToolUtils.getFunction(program, address);
            if (function == null) {
                throw new ToolExecutionException("Failed to retrieve function from address: " + address);
            }
            
            // Use transaction for program modification
            int transactionId = program.startTransaction("DecompAI: Rename local variable");
            try {
                // Decompile function to get HighFunction
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(program);
                
                try {
                    DecompileOptions options = new DecompileOptions();
                    decompiler.setOptions(options);
                    
                    DecompileResults results = decompiler.decompileFunction(
                        function,
                        30, // Timeout in seconds (getDefaultTimeout() removed in Ghidra 12.0)
                        context.getMonitor() != null ? context.getMonitor() : ghidra.util.task.TaskMonitor.DUMMY
                    );
                    
                    if (!results.decompileCompleted()) {
                        throw new ToolExecutionException("Failed to decompile function: " + 
                            (results.getErrorMessage() != null ? results.getErrorMessage() : "Unknown error"));
                    }
                    
                    // TODO: Implement variable renaming using HighFunction API
                    // This requires accessing HighVariable objects and renaming them
                    // For now, this is a placeholder
                    // In a full implementation, we'd use:
                    // HighFunction highFunction = results.getHighFunction();
                    // HighVariable var = highFunction.getLocalSymbolMap().getVariable(fromName);
                    // if (var != null) {
                    //     var.setName(toName);
                    // }
                    
                } finally {
                    decompiler.closeProgram();
                }
            } finally {
                program.endTransaction(transactionId, true);
            }
        } catch (ToolExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new ToolExecutionException("Failed to rename local variable: " + e.getMessage(), e);
        }
    }
}

