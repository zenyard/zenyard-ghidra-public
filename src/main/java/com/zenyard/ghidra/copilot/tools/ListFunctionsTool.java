package com.zenyard.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;

import com.zenyard.ghidra.copilot.tools.models.Function;
import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

/**
 * Tool to list functions with optional regex filter.
 */
public class ListFunctionsTool {
    
    private final CopilotToolContext context;
    
    public ListFunctionsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("List program functions with names and addresses. Optional `filter` regex matches function names.")
    public ToolOutput listFunctions(
            @P(value = "Optional regex filter for function names.", required = false) String filter) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        if (filter != null) {
            args.put("filter", filter);
        }
        return ToolUtils.executeTool(context, "list_functions", args, () -> {
            try {
                context.checkCancelled();
                java.util.regex.Pattern pattern = filter != null && !filter.isBlank()
                    ? java.util.regex.Pattern.compile(filter)
                    : null;
                StringBuilder output = new StringBuilder();
                int count = 0;
                ghidra.program.model.listing.FunctionIterator iterator =
                    context.getProgram().getFunctionManager().getFunctions(true);
                while (iterator.hasNext()) {
                    ghidra.program.model.listing.Function func = iterator.next();
                    String name = func.getName(true);
                    if (pattern != null && (name == null || !pattern.matcher(name).find())) {
                        continue;
                    }
                    Function mapped = Function.fromGhidraFunction(func, context.getProgram());
                    output.append(mapped.getName())
                        .append(" ")
                        .append(mapped.getAddress())
                        .append("\n");
                    count++;
                }
                return ToolUtils.persistLargeOutput(context, "functions", output.toString(), count);
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list functions: " + e.getMessage(), e);
            }
        });
    }
}

