package com.zenyard.ghidra.copilot.tools;

import java.util.function.Predicate;
import java.util.regex.Pattern;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;

import com.zenyard.ghidra.copilot.tools.models.Function;
import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

/**
 * Tool to search functions by comment regex pattern.
 */
public class SearchFunctionCommentsTool {
    
    private final CopilotToolContext context;
    
    public SearchFunctionCommentsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Search function comments using a regex pattern and return matching functions.")
    public ToolOutput searchFunctionComments(
            @P("Java regex pattern matched against each function comment.") String regex) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("regex", regex);
        return ToolUtils.executeTool(context, "search_function_comments", args, () -> {
            try {
                context.checkCancelled();

                // Compile regex pattern
                Pattern pattern;
                try {
                    pattern = Pattern.compile(regex);
                } catch (Exception e) {
                    throw new ToolExecutionException("Invalid regex pattern: " + e.getMessage());
                }

                final Pattern finalPattern = pattern;

                java.util.List<Function> results = new java.util.ArrayList<>();
                ghidra.program.model.listing.FunctionIterator iterator =
                    context.getProgram().getFunctionManager().getFunctions(true);
                while (iterator.hasNext()) {
                    ghidra.program.model.listing.Function func = iterator.next();
                    String comment = func.getComment();
                    if (comment != null && finalPattern.matcher(comment).find()) {
                        boolean swiftSourceAvailable = false; // TODO: Implement Swift detection
                        results.add(new Function(
                            func.getName(),
                            ToolUtils.formatAddress(func.getEntryPoint()),
                            swiftSourceAvailable
                        ));
                    }
                }

                StringBuilder output = new StringBuilder();
                for (Function func : results) {
                    output.append(func.getName())
                        .append(" ")
                        .append(func.getAddress())
                        .append("\n");
                }
                return ToolUtils.persistLargeOutput(context, "function-comments", output.toString(), results.size());
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to search function comments: " + e.getMessage(), e);
            }
        });
    }
}

