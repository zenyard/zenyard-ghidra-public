package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import com.zenyard.ghidra.copilot.tools.models.PagedResults;

/**
 * Tool to list exported symbols (entry points).
 */
public class ListExportsTool {
    
    private final CopilotToolContext context;
    
    public ListExportsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a paginated list of exported symbols (entry points) in the program. " +
          "If next_cursor is not empty, there are more pages which can be fetched using the cursor parameter.")
    public PagedResults<String> listExports(String cursor) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        if (cursor != null) {
            args.put("cursor", cursor);
        }
        return ToolUtils.executeTool(context, "list_exports", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                SymbolTable symbolTable = program.getSymbolTable();
                SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
                
                List<String> allExports = new ArrayList<>();
                
                // Parse cursor (use symbol name as cursor)
                String cursorName = cursor;
                boolean pastCursor = (cursorName == null);
                
                while (allSymbols.hasNext()) {
                    context.checkCancelled();
                    
                    Symbol symbol = allSymbols.next();
                    
                    // Check if it's an entry point
                    if (!symbol.isExternalEntryPoint()) {
                        continue;
                    }
                    
                    String symbolName = symbol.getName();
                    
                    // Skip until past cursor
                    if (!pastCursor) {
                        if (symbolName.compareTo(cursorName) > 0) {
                            pastCursor = true;
                        } else {
                            continue;
                        }
                    }
                    
                    String exportStr = symbolName + " -> " + ToolUtils.formatAddress(symbol.getAddress());
                    allExports.add(exportStr);
                }
                
                // Paginate
                int pageSize = 200;
                List<String> pageExports;
                String nextCursor = null;
                
                if (allExports.size() > pageSize) {
                    pageExports = allExports.subList(0, pageSize);
                    // Extract symbol name from last export string
                    String lastExport = pageExports.get(pageSize - 1);
                    int arrowIndex = lastExport.indexOf(" -> ");
                    if (arrowIndex > 0) {
                        nextCursor = lastExport.substring(0, arrowIndex);
                    } else {
                        nextCursor = lastExport;
                    }
                } else {
                    pageExports = allExports;
                }
                
                return new PagedResults<>(pageExports, nextCursor);
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list exports: " + e.getMessage(), e);
            }
        });
    }
}
