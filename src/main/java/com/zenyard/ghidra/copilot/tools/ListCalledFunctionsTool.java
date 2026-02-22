package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import com.zenyard.ghidra.copilot.tools.models.Function;
import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

/**
 * Tool to list functions called BY a function (callees).
 * This is the complement to ListCallingFunctionsTool which gets callers.
 */
public class ListCalledFunctionsTool {
    
    private final CopilotToolContext context;
    
    public ListCalledFunctionsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("List callee functions called by a given function. This is the inverse of `listCallingFunctions`.")
    public ToolOutput listCalledFunctions(
            @P("Source function address (hex like `0x401000`).") String address) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        return ToolUtils.executeTool(context, "list_called_functions", args, () -> {
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

                ReferenceManager refManager = program.getReferenceManager();
                FunctionManager functionManager = program.getFunctionManager();
                
                // Get all references from this function
                Address entryPoint = function.getEntryPoint();
                Address endAddress = function.getBody().getMaxAddress();
                
                Set<ghidra.program.model.listing.Function> calledFunctions = new HashSet<>();
                
                // Iterate through all addresses in the function
                Address currentAddr = entryPoint;
                while (currentAddr.compareTo(endAddress) <= 0) {
                    context.checkCancelled();
                    
                    Reference[] refs = refManager.getReferencesFrom(currentAddr);
                    for (Reference ref : refs) {
                        // Check if it's a call reference
                        if (ref.getReferenceType().isCall()) {
                            Address targetAddr = ref.getToAddress();
                            ghidra.program.model.listing.Function calledFunc = functionManager.getFunctionAt(targetAddr);
                            if (calledFunc != null) {
                                calledFunctions.add(calledFunc);
                            }
                        }
                    }
                    
                    // Move to next address (simplified - in practice would use instruction iterator)
                    currentAddr = currentAddr.next();
                    if (currentAddr == null) {
                        break;
                    }
                }
                
                // Convert to sorted list
                List<ghidra.program.model.listing.Function> sortedFunctions = new ArrayList<>(calledFunctions);
                sortedFunctions.sort((f1, f2) -> f1.getEntryPoint().compareTo(f2.getEntryPoint()));
                
                // Map to tool Function objects
                List<Function> results = new ArrayList<>();
                for (ghidra.program.model.listing.Function func : sortedFunctions) {
                    results.add(Function.fromGhidraFunction(func, program));
                }
                StringBuilder output = new StringBuilder();
                for (Function func : results) {
                    output.append(func.getName())
                        .append(" ")
                        .append(func.getAddress())
                        .append("\n");
                }
                return ToolUtils.persistLargeOutput(context, "called-functions", output.toString(), results.size());
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list called functions: " + e.getMessage(), e);
            }
        });
    }
}
