package com.zenyard.decompai.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;

/**
 * Tool to decompile a function to C code.
 */
public class DecompileFunctionTool {
    
    private final CopilotToolContext context;
    
    public DecompileFunctionTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns the decompiled code of the given function")
    public String decompileFunction(String address) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        return ToolUtils.executeTool(context, "decompile_function", args, () -> {
            try {
                context.checkCancelled();

                ghidra.program.model.listing.Function function = ToolUtils.getFunction(context.getProgram(), address);
                if (function == null) {
                    throw new ToolExecutionException("Failed to retrieve function from address: " + address);
                }

                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(context.getProgram());

                try {
                    DecompileOptions options = new DecompileOptions();
                    decompiler.setOptions(options);

                    TaskMonitor monitor = context.getMonitor();
                    DecompileResults results = decompiler.decompileFunction(
                        function,
                        30, // Timeout in seconds (getDefaultTimeout() removed in Ghidra 12.0)
                        monitor != null ? monitor : TaskMonitor.DUMMY
                    );

                    if (!results.decompileCompleted()) {
                        String errorMsg = results.getErrorMessage();
                        throw new ToolExecutionException("Can't decompile: "
                            + (errorMsg != null ? errorMsg : "Unknown error"));
                    }

                    return results.getDecompiledFunction().getC();
                } finally {
                    decompiler.closeProgram();
                }
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to decompile function: " + e.getMessage(), e);
            }
        });
    }
}

