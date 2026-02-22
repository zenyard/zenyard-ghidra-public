package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

/**
 * Tool to list exported symbols (entry points).
 */
public class ListExportsTool {
    
    private final CopilotToolContext context;
    
    public ListExportsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a list of exported symbols (entry points) in the program.")
    public ToolOutput listExports() {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
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
                
                while (allSymbols.hasNext()) {
                    context.checkCancelled();
                    
                    Symbol symbol = allSymbols.next();
                    
                    // Check if it's an entry point
                    if (!symbol.isExternalEntryPoint()) {
                        continue;
                    }
                    
                    String symbolName = symbol.getName();
                    
                    String exportStr = symbolName + " -> " + ToolUtils.formatAddress(symbol.getAddress());
                    allExports.add(exportStr);
                }

                StringBuilder output = new StringBuilder();
                for (String entry : allExports) {
                    output.append(entry).append("\n");
                }
                return ToolUtils.persistLargeOutput(context, "exports", output.toString(), allExports.size());
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list exports: " + e.getMessage(), e);
            }
        });
    }
}
