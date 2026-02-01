package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import com.zenyard.ghidra.copilot.tools.models.PagedResults;
import com.zenyard.ghidra.copilot.tools.models.Xref;

/**
 * Tool to get all references FROM an address.
 */
public class GetXrefsFromTool {
    
    private final CopilotToolContext context;
    
    public GetXrefsFromTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns all references FROM the given address. " +
          "This includes all reference types (calls, data references, etc.). " +
          "If next_cursor is not empty, there are more pages which can be fetched using the cursor parameter.")
    public PagedResults<Xref> getXrefsFrom(String address, String cursor) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        if (cursor != null) {
            args.put("cursor", cursor);
        }
        return ToolUtils.executeTool(context, "get_xrefs_from", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Address fromAddress = ToolUtils.parseAddress(program, address);
                if (fromAddress == null) {
                    throw new ToolExecutionException("Invalid address: " + address);
                }

                ReferenceManager refManager = program.getReferenceManager();
                Reference[] references = refManager.getReferencesFrom(fromAddress);
                
                List<Xref> allXrefs = new ArrayList<>();
                FunctionManager functionManager = program.getFunctionManager();
                
                // Parse cursor
                Address cursorAddress = cursor != null ? ToolUtils.parseAddress(program, cursor) : null;
                boolean pastCursor = (cursorAddress == null);
                
                for (Reference ref : references) {
                    context.checkCancelled();
                    
                    Address toAddress = ref.getToAddress();
                    
                    // Skip until past cursor
                    if (!pastCursor) {
                        if (toAddress.compareTo(cursorAddress) > 0) {
                            pastCursor = true;
                        } else {
                            continue;
                        }
                    }
                    
                    // Get context (target function name or data label)
                    String contextStr = "";
                    Function toFunc = functionManager.getFunctionAt(toAddress);
                    if (toFunc != null) {
                        contextStr = toFunc.getName();
                    } else {
                        Data data = program.getListing().getDataAt(toAddress);
                        if (data != null && data.getLabel() != null) {
                            contextStr = data.getLabel();
                        }
                    }
                    
                    String refType = ref.getReferenceType().getName();
                    
                    allXrefs.add(new Xref(
                        ToolUtils.formatAddress(fromAddress),
                        ToolUtils.formatAddress(toAddress),
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
                    nextCursor = pageXrefs.get(pageSize - 1).getToAddress();
                } else {
                    pageXrefs = allXrefs;
                }
                
                return new PagedResults<>(pageXrefs, nextCursor);
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to get xrefs from address: " + e.getMessage(), e);
            }
        });
    }
}
