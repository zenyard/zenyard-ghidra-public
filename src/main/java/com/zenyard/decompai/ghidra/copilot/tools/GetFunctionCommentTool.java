package com.zenyard.decompai.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.listing.Function;

/**
 * Tool to get function documentation/comment.
 */
public class GetFunctionCommentTool {
    
    private final CopilotToolContext context;
    
    public GetFunctionCommentTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns the function documentation for the given function")
    public String getFunctionComment(String address) {
        try {
            context.checkCancelled();
            
            Function function = ToolUtils.getFunction(context.getProgram(), address);
            if (function == null) {
                throw new ToolExecutionException("Failed to retrieve function from address: " + address);
            }
            
            String comment = function.getComment();
            return comment != null ? comment : "";
        } catch (ToolExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new ToolExecutionException("Failed to get function comment: " + e.getMessage(), e);
        }
    }
}

