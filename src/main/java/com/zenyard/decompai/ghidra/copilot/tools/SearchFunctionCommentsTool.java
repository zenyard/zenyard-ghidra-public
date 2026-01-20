package com.zenyard.decompai.ghidra.copilot.tools;

import java.util.function.Predicate;
import java.util.regex.Pattern;

import dev.langchain4j.agent.tool.Tool;

import com.zenyard.decompai.ghidra.copilot.tools.models.Function;
import com.zenyard.decompai.ghidra.copilot.tools.models.PagedResults;

/**
 * Tool to search functions by comment regex pattern.
 */
public class SearchFunctionCommentsTool {
    
    private final CopilotToolContext context;
    
    public SearchFunctionCommentsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a paginated list of functions with comments matching the given regex pattern")
    public PagedResults<Function> searchFunctionComments(String regex, String cursor) {
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
            
            // Create predicate to filter functions by comment
            Predicate<ghidra.program.model.listing.Function> commentMatches = func -> {
                String comment = func.getComment();
                return comment != null && finalPattern.matcher(comment).find();
            };
            
            // Map function to tool Function
            java.util.function.Function<ghidra.program.model.listing.Function, com.zenyard.decompai.ghidra.copilot.tools.models.Function> mapper = func -> {
                boolean swiftSourceAvailable = false; // TODO: Implement Swift detection
                return new Function(
                    func.getName(),
                    ToolUtils.formatAddress(func.getEntryPoint()),
                    swiftSourceAvailable
                );
            };
            
            return PaginationHelper.paginateFunctions(
                context.getProgram(),
                cursor,
                null, // No name filter
                mapper,
                commentMatches
            );
        } catch (ToolExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new ToolExecutionException("Failed to search function comments: " + e.getMessage(), e);
        }
    }
}

