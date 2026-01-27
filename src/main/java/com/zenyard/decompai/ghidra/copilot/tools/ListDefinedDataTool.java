package com.zenyard.decompai.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import com.zenyard.decompai.ghidra.copilot.tools.models.PagedResults;

/**
 * Tool to list defined data (global data structures).
 */
public class ListDefinedDataTool {
    
    private final CopilotToolContext context;
    
    public ListDefinedDataTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a paginated list of defined data (global data structures) in the program. " +
          "If next_cursor is not empty, there are more pages which can be fetched using the cursor parameter.")
    public PagedResults<String> listDefinedData(String cursor) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        if (cursor != null) {
            args.put("cursor", cursor);
        }
        return ToolUtils.executeTool(context, "list_defined_data", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Listing listing = program.getListing();
                DataIterator dataIt = listing.getDefinedData(true);
                
                List<String> allData = new ArrayList<>();
                
                // Parse cursor
                Address cursorAddress = cursor != null ? ToolUtils.parseAddress(program, cursor) : null;
                boolean pastCursor = (cursorAddress == null);
                
                while (dataIt.hasNext()) {
                    context.checkCancelled();
                    
                    Data data = dataIt.next();
                    if (data == null) {
                        continue;
                    }
                    
                    Address addr = data.getAddress();
                    
                    // Skip until past cursor
                    if (!pastCursor) {
                        if (addr.compareTo(cursorAddress) > 0) {
                            pastCursor = true;
                        } else {
                            continue;
                        }
                    }
                    
                    String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valueRepr = "";
                    try {
                        valueRepr = data.getDefaultValueRepresentation();
                    } catch (Exception e) {
                        valueRepr = "(unreadable)";
                    }
                    
                    String dataStr = String.format("%s: %s = %s",
                        ToolUtils.formatAddress(addr),
                        label,
                        valueRepr);
                    allData.add(dataStr);
                }
                
                // Paginate
                int pageSize = 200;
                List<String> pageData;
                String nextCursor = null;
                
                if (allData.size() > pageSize) {
                    pageData = allData.subList(0, pageSize);
                    // Extract address from last data string
                    String lastData = pageData.get(pageSize - 1);
                    int colonIndex = lastData.indexOf(':');
                    if (colonIndex > 0) {
                        nextCursor = lastData.substring(0, colonIndex).trim();
                    }
                } else {
                    pageData = allData;
                }
                
                return new PagedResults<>(pageData, nextCursor);
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list defined data: " + e.getMessage(), e);
            }
        });
    }
}
