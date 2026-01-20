package com.zenyard.decompai.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import com.zenyard.decompai.ghidra.copilot.tools.models.Function;
import com.zenyard.decompai.ghidra.copilot.tools.models.PagedResults;

/**
 * Tool to list functions that call a given function.
 */
public class ListCallingFunctionsTool {
    
    private final CopilotToolContext context;
    
    public ListCallingFunctionsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a list of functions that call the given function. " +
          "If next_cursor is not empty, there are more pages which can be fetched using the cursor parameter.")
    public PagedResults<Function> listCallingFunctions(String address, String cursor) {
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
            Address cursorAddress = cursor != null ? ToolUtils.parseAddress(program, cursor) : null;
            boolean pastCursor = (cursorAddress == null);
            
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
                    // Check cursor
                    if (!pastCursor) {
                        if (callingFunction.getEntryPoint().compareTo(cursorAddress) > 0) {
                            pastCursor = true;
                        } else {
                            continue;
                        }
                    }
                    
                    // Check if already added (avoid duplicates)
                    if (!callingFunctions.contains(callingFunction)) {
                        callingFunctions.add(callingFunction);
                    }
                }
            }
            
            // Sort by address
            callingFunctions.sort((f1, f2) -> f1.getEntryPoint().compareTo(f2.getEntryPoint()));
            
            // Paginate
            int pageSize = 200;
            List<ghidra.program.model.listing.Function> pageFunctions;
            String nextCursor = null;
            
            if (callingFunctions.size() > pageSize) {
                pageFunctions = callingFunctions.subList(0, pageSize);
                nextCursor = ToolUtils.formatAddress(pageFunctions.get(pageSize - 1).getEntryPoint());
            } else {
                pageFunctions = callingFunctions;
            }
            
            // Map to tool Function objects
            List<Function> results = new ArrayList<>();
            for (ghidra.program.model.listing.Function func : pageFunctions) {
                boolean swiftSourceAvailable = false; // TODO: Implement Swift detection
                results.add(new Function(
                    func.getName(),
                    ToolUtils.formatAddress(func.getEntryPoint()),
                    swiftSourceAvailable
                ));
            }
            
            return new PagedResults<>(results, nextCursor);
        } catch (ToolExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new ToolExecutionException("Failed to list calling functions: " + e.getMessage(), e);
        }
    }
}

