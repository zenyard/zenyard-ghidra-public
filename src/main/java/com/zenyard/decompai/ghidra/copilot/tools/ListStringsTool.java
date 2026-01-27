package com.zenyard.decompai.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import com.zenyard.decompai.ghidra.copilot.tools.models.PagedResults;
import com.zenyard.decompai.ghidra.copilot.tools.models.StringData;

/**
 * Tool to list string literals in the binary.
 */
public class ListStringsTool {
    
    private final CopilotToolContext context;
    
    public ListStringsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a paginated list of string literals found in the binary. " +
          "An optional filter can be provided to search for strings containing specific text. " +
          "If next_cursor is not empty, there are more pages which can be fetched using the cursor parameter.")
    public PagedResults<StringData> listStrings(String filter, String cursor) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        if (filter != null) {
            args.put("filter", filter);
        }
        if (cursor != null) {
            args.put("cursor", cursor);
        }
        return ToolUtils.executeTool(context, "list_strings", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                // Compile filter pattern if provided
                Pattern filterPattern = null;
                if (filter != null && !filter.isEmpty()) {
                    try {
                        filterPattern = Pattern.compile(filter, Pattern.CASE_INSENSITIVE);
                    } catch (Exception e) {
                        throw new ToolExecutionException("Invalid regex pattern: " + e.getMessage());
                    }
                }

                Listing listing = program.getListing();
                DataIterator dataIt = listing.getDefinedData(true);
                
                List<StringData> allStrings = new ArrayList<>();
                
                // Parse cursor
                Address cursorAddress = cursor != null ? ToolUtils.parseAddress(program, cursor) : null;
                boolean pastCursor = (cursorAddress == null);
                
                while (dataIt.hasNext()) {
                    context.checkCancelled();
                    
                    Data data = dataIt.next();
                    if (data == null) {
                        continue;
                    }
                    
                    // Check if it's a string type
                    if (!isStringData(data)) {
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
                    
                    String value = "";
                    try {
                        Object valueObj = data.getValue();
                        if (valueObj != null) {
                            value = valueObj.toString();
                        }
                    } catch (Exception e) {
                        // Skip if we can't read the value
                        continue;
                    }
                    
                    // Apply filter if provided
                    if (filterPattern != null && !filterPattern.matcher(value).find()) {
                        continue;
                    }
                    
                    DataType dt = data.getDataType();
                    String dataTypeName = dt != null ? dt.getName().toLowerCase() : "string";
                    int length = value.length();
                    
                    allStrings.add(new StringData(
                        ToolUtils.formatAddress(addr),
                        value,
                        dataTypeName,
                        length
                    ));
                }
                
                // Paginate
                int pageSize = 200;
                List<StringData> pageStrings;
                String nextCursor = null;
                
                if (allStrings.size() > pageSize) {
                    pageStrings = allStrings.subList(0, pageSize);
                    nextCursor = pageStrings.get(pageSize - 1).getAddress();
                } else {
                    pageStrings = allStrings;
                }
                
                return new PagedResults<>(pageStrings, nextCursor);
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list strings: " + e.getMessage(), e);
            }
        });
    }
    
    /**
     * Check if the given data is a string type.
     */
    private boolean isStringData(Data data) {
        if (data == null) {
            return false;
        }
        
        DataType dt = data.getDataType();
        if (dt == null) {
            return false;
        }
        
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }
}
