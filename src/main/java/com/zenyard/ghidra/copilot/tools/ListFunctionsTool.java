package com.zenyard.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;

import com.zenyard.ghidra.copilot.tools.models.Function;
import com.zenyard.ghidra.copilot.tools.models.PagedResults;

/**
 * Tool to list functions with optional regex filter.
 */
public class ListFunctionsTool {
    
    private final CopilotToolContext context;
    
    public ListFunctionsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a paginated list of functions (names and addresses) from the program. " 
          + "An optional regex filter can be provided to filter by function name. " 
          + "If next_cursor is not empty, there are more pages which can be fetched using the cursor parameter.")
    public PagedResults<Function> listFunctions(String filter, String cursor) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        if (filter != null) {
            args.put("filter", filter);
        }
        if (cursor != null) {
            args.put("cursor", cursor);
        }
        return ToolUtils.executeTool(context, "list_functions", args, () -> {
            try {
                context.checkCancelled();

                // Map Ghidra Function to tool Function
                return PaginationHelper.paginateFunctions(
                    context.getProgram(),
                    cursor,
                    filter,
                    func -> Function.fromGhidraFunction(func, context.getProgram())
                );
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list functions: " + e.getMessage(), e);
            }
        });
    }
}

