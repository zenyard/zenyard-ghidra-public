package com.zenyard.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.zenyard.ghidra.copilot.tools.models.Function;
import com.zenyard.ghidra.copilot.tools.models.ToolOutput;
import com.zenyard.ghidra.api.generated.model.SwiftFunction;

/**
 * Tool to search functions by Swift source regex pattern.
 * Mirrors search_swift_functions in zenyard_ida/copilot_tools.py
 */
public class SearchSwiftFunctionsTool {
    
    private final CopilotToolContext context;
    private final Program program;
    
    public SearchSwiftFunctionsTool(CopilotToolContext context) {
        this.context = context;
        this.program = context.getProgram();
    }
    
    @Tool("Search functions whose inferred Swift source matches a regex pattern.")
    public ToolOutput searchSwiftFunctions(
            @P("Java regex pattern matched against Swift source text.") String regex) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("regex", regex);
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

                java.util.List<Function> results = new java.util.ArrayList<>();
                ghidra.program.model.listing.FunctionIterator iterator =
                    program.getFunctionManager().getFunctions(true);
                while (iterator.hasNext()) {
                    ghidra.program.model.listing.Function func = iterator.next();
                    Address functionAddress = func.getEntryPoint();
                    SwiftFunction swiftFunction = SwiftUtils.findLatestSwiftFunctionInference(
                        program, functionAddress);
                    if (swiftFunction == null || swiftFunction.getSource() == null
                        || swiftFunction.getSource().isEmpty()) {
                        continue;
                    }
                    if (pattern.matcher(swiftFunction.getSource()).find()) {
                        results.add(Function.fromGhidraFunction(func));
                    }
                }
                StringBuilder output = new StringBuilder();
                for (Function func : results) {
                    output.append(func.getName())
                        .append(" ")
                        .append(func.getAddress())
                        .append("\n");
                }
                return ToolUtils.persistLargeOutput(context, "swift-functions", output.toString(), results.size());

            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException(
                    "Failed to search Swift functions: " + e.getMessage(), e);
            }
        });
    }
}

