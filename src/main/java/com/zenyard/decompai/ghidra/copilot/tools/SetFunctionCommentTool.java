package com.zenyard.decompai.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Tool to set function documentation/comment.
 */
public class SetFunctionCommentTool {
    
    private final CopilotToolContext context;
    
    public SetFunctionCommentTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Sets the function documentation for the given function. Use 80 character lines and format this like a function documentation.")
    public void setFunctionComment(String address, String comment) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        args.put("comment", comment);
        ToolUtils.executeTool(context, "set_function_comment", args, () -> {
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
                int transactionId = program.startTransaction("DecompAI: Set function comment");
                try {
                    function.setComment(comment != null ? comment : "");
                } finally {
                    program.endTransaction(transactionId, true);
                }
                return null;
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to set function comment: " + e.getMessage(), e);
            }
        });
    }
}

