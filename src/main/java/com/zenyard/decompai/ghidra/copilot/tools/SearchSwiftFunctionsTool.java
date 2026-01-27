package com.zenyard.decompai.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.zenyard.decompai.ghidra.copilot.tools.models.Function;
import com.zenyard.decompai.ghidra.copilot.tools.models.PagedResults;
import com.zenyard.decompai.ghidra.api.generated.model.SwiftFunction;

/**
 * Tool to search functions by Swift source regex pattern.
 * Mirrors search_swift_functions in decompai_ida/copilot_tools.py
 */
public class SearchSwiftFunctionsTool {
    
    private final CopilotToolContext context;
    private final Program program;
    
    public SearchSwiftFunctionsTool(CopilotToolContext context) {
        this.context = context;
        this.program = context.getProgram();
    }
    
    @Tool("Returns a paginated list of functions with Swift source code matching the given regex pattern. " 
          + "If next_cursor is not empty, there are more pages which can be fetched using the cursor parameter.")
    public PagedResults<Function> searchSwiftFunctions(String regex, String cursor) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("regex", regex);
        if (cursor != null) {
            args.put("cursor", cursor);
        }
        return ToolUtils.executeTool(context, "search_swift_functions", args, () -> {
            try {
                context.checkCancelled();

                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                // Compile regex pattern
                Pattern pattern;
                try {
                    pattern = Pattern.compile(regex);
                } catch (PatternSyntaxException e) {
                    throw new ToolExecutionException(
                        "Invalid regex pattern: " + regex + ". " + e.getMessage(), e);
                }

                // Use pagination helper with filter for Swift functions matching regex
                return PaginationHelper.paginateFunctions(
                    program,
                    cursor,
                    null, // No name filter
                    func -> Function.fromGhidraFunction(func),
                    func -> {
                        // Additional filter: check if Swift source matches regex
                        Address functionAddress = func.getEntryPoint();
                        SwiftFunction swiftFunction = SwiftUtils.findLatestSwiftFunctionInference(
                            program, functionAddress);
                        if (swiftFunction == null || swiftFunction.getSource() == null
                            || swiftFunction.getSource().isEmpty()) {
                            return false; // Skip functions without Swift source
                        }
                        // Check if Swift source matches regex
                        return pattern.matcher(swiftFunction.getSource()).find();
                    }
                );

            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException(
                    "Failed to search Swift functions: " + e.getMessage(), e);
            }
        });
    }
}

