package com.zenyard.decompai.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import com.zenyard.decompai.ghidra.copilot.tools.models.PagedResults;

/**
 * Tool to list imported symbols (external symbols).
 */
public class ListImportsTool {
    
    private final CopilotToolContext context;
    
    public ListImportsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a paginated list of imported symbols (external symbols) in the program. " +
          "If next_cursor is not empty, there are more pages which can be fetched using the cursor parameter.")
    public PagedResults<String> listImports(String cursor) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        if (cursor != null) {
            args.put("cursor", cursor);
        }
        return ToolUtils.executeTool(context, "list_imports", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                SymbolTable symbolTable = program.getSymbolTable();
                SymbolIterator externalSymbols = symbolTable.getExternalSymbols();
                
                List<String> allImports = new ArrayList<>();
                
                // Parse cursor (use symbol name as cursor)
                String cursorName = cursor;
                boolean pastCursor = (cursorName == null);
                
                while (externalSymbols.hasNext()) {
                    context.checkCancelled();
                    
                    Symbol symbol = externalSymbols.next();
                    String symbolName = symbol.getName();
                    
                    // Skip until past cursor
                    if (!pastCursor) {
                        if (symbolName.compareTo(cursorName) > 0) {
                            pastCursor = true;
                        } else {
                            continue;
                        }
                    }
                    
                    String importStr = symbolName + " -> " + ToolUtils.formatAddress(symbol.getAddress());
                    allImports.add(importStr);
                }
                
                // Paginate
                int pageSize = 200;
                List<String> pageImports;
                String nextCursor = null;
                
                if (allImports.size() > pageSize) {
                    pageImports = allImports.subList(0, pageSize);
                    // Extract symbol name from last import string
                    String lastImport = pageImports.get(pageSize - 1);
                    int arrowIndex = lastImport.indexOf(" -> ");
                    if (arrowIndex > 0) {
                        nextCursor = lastImport.substring(0, arrowIndex);
                    } else {
                        nextCursor = lastImport;
                    }
                } else {
                    pageImports = allImports;
                }
                
                return new PagedResults<>(pageImports, nextCursor);
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list imports: " + e.getMessage(), e);
            }
        });
    }
}
