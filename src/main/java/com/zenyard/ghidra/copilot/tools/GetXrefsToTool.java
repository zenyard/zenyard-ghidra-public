package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import com.zenyard.ghidra.copilot.tools.models.PagedResults;
import com.zenyard.ghidra.copilot.tools.models.Xref;

/**
 * Tool to get all references TO an address.
 */
public class GetXrefsToTool {
    
    private final CopilotToolContext context;
    
    public GetXrefsToTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns all references TO the given address. " +
          "This includes all reference types (calls, data references, etc.). " +
          "If next_cursor is not empty, there are more pages which can be fetched using the cursor parameter.")
    public PagedResults<Xref> getXrefsTo(String address, String cursor) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        if (cursor != null) {
            args.put("cursor", cursor);
        }
        return ToolUtils.executeTool(context, "get_xrefs_to", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Address targetAddress = ToolUtils.parseAddress(program, address);
                if (targetAddress == null) {
                    throw new ToolExecutionException("Invalid address: " + address);
                }

                ReferenceManager refManager = program.getReferenceManager();
                ReferenceIterator refIter = refManager.getReferencesTo(targetAddress);
                
                List<Xref> allXrefs = new ArrayList<>();
                FunctionManager functionManager = program.getFunctionManager();
                
                // Parse cursor
                Address cursorAddress = cursor != null ? ToolUtils.parseAddress(program, cursor) : null;
                boolean pastCursor = (cursorAddress == null);
                
                while (refIter.hasNext()) {
                    context.checkCancelled();
                    
                    Reference ref = refIter.next();
                    Address fromAddress = ref.getFromAddress();
                    
                    // Skip until past cursor
                    if (!pastCursor) {
                        if (fromAddress.compareTo(cursorAddress) > 0) {
                            pastCursor = true;
                        } else {
                            continue;
                        }
                    }
                    
                    // Get context (function name if in a function)
                    Function fromFunc = functionManager.getFunctionContaining(fromAddress);
                    String contextStr = fromFunc != null ? fromFunc.getName() : "";
                    
                    String refType = ref.getReferenceType().getName();
                    
                    allXrefs.add(new Xref(
                        ToolUtils.formatAddress(fromAddress),
                        ToolUtils.formatAddress(targetAddress),
                        refType,
                        contextStr
                    ));
                }
                
                // Paginate
                int pageSize = 200;
                List<Xref> pageXrefs;
                String nextCursor = null;
                
                if (allXrefs.size() > pageSize) {
                    pageXrefs = allXrefs.subList(0, pageSize);
                    nextCursor = pageXrefs.get(pageSize - 1).getFromAddress();
                } else {
                    pageXrefs = allXrefs;
                }
                
                return new PagedResults<>(pageXrefs, nextCursor);
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to get xrefs to address: " + e.getMessage(), e);
            }
        });
    }
}
