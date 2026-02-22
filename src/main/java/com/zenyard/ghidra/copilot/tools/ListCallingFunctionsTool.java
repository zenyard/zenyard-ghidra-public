package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import com.zenyard.ghidra.copilot.tools.models.Function;
import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

/**
 * Tool to list functions that call a given function.
 */
public class ListCallingFunctionsTool {
    
    private final CopilotToolContext context;
    
    public ListCallingFunctionsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("List caller functions that reference a target function via call edges.")
    public ToolOutput listCallingFunctions(
            @P("Target function address (hex like `0x401000`).") String address) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        return ToolUtils.executeTool(context, "list_calling_functions", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                ghidra.program.model.listing.Function targetFunction = ToolUtils.getFunction(program, address);
                if (targetFunction == null) {
                    throw new ToolExecutionException("Failed to retrieve function from address: " + address);
                }

                // Get references to this function
                ReferenceManager refManager = program.getReferenceManager();
                Address entryPoint = targetFunction.getEntryPoint();
                // In Ghidra 12.0, getReferencesTo returns ReferenceIterator, convert to list
                ghidra.program.model.symbol.ReferenceIterator refsIter = refManager.getReferencesTo(entryPoint);
                List<Reference> refs = new ArrayList<>();
                while (refsIter.hasNext()) {
                    refs.add(refsIter.next());
                }

                // Collect calling functions
                FunctionManager functionManager = program.getFunctionManager();
                List<ghidra.program.model.listing.Function> callingFunctions = new ArrayList<>();
                for (Reference ref : refs) {
                    // Only consider call references
                    // In Ghidra 12.0, use getReferenceType() and check if it's a call
                    ghidra.program.model.symbol.RefType refType = ref.getReferenceType();
                    // Check if it's any type of call (conditional or unconditional)
                    if (!refType.isCall()) {
                        continue;
                    }

                    Address fromAddress = ref.getFromAddress();
                    ghidra.program.model.listing.Function callingFunction = functionManager.getFunctionContaining(fromAddress);

                    if (callingFunction != null) {
                        // Check if already added (avoid duplicates)
                        if (!callingFunctions.contains(callingFunction)) {
                            callingFunctions.add(callingFunction);
                        }
                    }
                }

                // Sort by address
                callingFunctions.sort((f1, f2) -> f1.getEntryPoint().compareTo(f2.getEntryPoint()));

                // Map to tool Function objects
                List<Function> results = new ArrayList<>();
                for (ghidra.program.model.listing.Function func : callingFunctions) {
                    boolean swiftSourceAvailable = false; // TODO: Implement Swift detection
                    results.add(new Function(
                        func.getName(),
                        ToolUtils.formatAddress(func.getEntryPoint()),
                        swiftSourceAvailable
                    ));
                }
                StringBuilder output = new StringBuilder();
                for (Function func : results) {
                    output.append(func.getName())
                        .append(" ")
                        .append(func.getAddress())
                        .append("\n");
                }
                return ToolUtils.persistLargeOutput(context, "calling-functions", output.toString(), results.size());
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list calling functions: " + e.getMessage(), e);
            }
        });
    }
}

