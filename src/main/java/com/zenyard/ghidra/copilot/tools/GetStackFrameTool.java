package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;

/**
 * Tool to get stack frame information (local variables and parameters) for a function.
 */
public class GetStackFrameTool {
    
    private final CopilotToolContext context;
    
    public GetStackFrameTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Return stack-frame details for one function, including locals, parameters, and frame offsets.")
    public String getStackFrame(
            @P("Function address (hex like `0x401000`).") String address) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        return ToolUtils.executeTool(context, "get_stack_frame", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                ghidra.program.model.listing.Function function = ToolUtils.getFunction(program, address);
                if (function == null) {
                    throw new ToolExecutionException("Failed to retrieve function from address: " + address);
                }

                StackFrame stackFrame = function.getStackFrame();
                if (stackFrame == null) {
                    throw new ToolExecutionException("No stack frame available for function");
                }

                StringBuilder result = new StringBuilder();
                
                result.append(String.format("Stack Frame for function: %s\n", function.getName()));
                result.append(String.format("Frame Size: %d bytes\n", stackFrame.getFrameSize()));
                result.append(String.format("Local Size: %d bytes\n", stackFrame.getLocalSize()));
                result.append(String.format("Parameter Size: %d bytes\n", stackFrame.getParameterSize()));
                result.append(String.format("Parameter Offset: %d\n", stackFrame.getParameterOffset()));
                result.append(String.format("Return Address Offset: %d\n", stackFrame.getReturnAddressOffset()));
                result.append("\n");
                
                // Parameters
                Variable[] allVariables = stackFrame.getStackVariables();
                List<Parameter> parameters = new ArrayList<>();
                for (Variable var : allVariables) {
                    if (var instanceof Parameter) {
                        parameters.add((Parameter) var);
                    }
                }
                if (parameters.size() > 0) {
                    result.append("Parameters:\n");
                    for (Parameter param : parameters) {
                        DataType dt = param.getDataType();
                        result.append(String.format("  %s: %s (offset: %d, ordinal: %d)\n",
                            param.getName(),
                            dt != null ? dt.getName() : "unknown",
                            param.getStackOffset(),
                            param.getOrdinal()));
                    }
                    result.append("\n");
                }
                
                // Local variables
                Variable[] locals = stackFrame.getLocals();
                if (locals.length > 0) {
                    result.append("Local Variables:\n");
                    for (Variable local : locals) {
                        DataType dt = local.getDataType();
                        result.append(String.format("  %s: %s (offset: %d)\n",
                            local.getName(),
                            dt != null ? dt.getName() : "unknown",
                            local.getStackOffset()));
                    }
                } else {
                    result.append("No local variables defined.\n");
                }
                
                return result.toString();
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to get stack frame: " + e.getMessage(), e);
            }
        });
    }
}
