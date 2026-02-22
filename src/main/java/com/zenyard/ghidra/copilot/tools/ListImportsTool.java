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
 * Tool to list imported symbols (external symbols).
 */
public class ListImportsTool {
    
    private final CopilotToolContext context;
    
    public ListImportsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a list of imported symbols (external symbols) in the program.")
    public ToolOutput listImports() {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
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
                
                while (externalSymbols.hasNext()) {
                    context.checkCancelled();
                    
                    Symbol symbol = externalSymbols.next();
                    String symbolName = symbol.getName();
                    
                    String importStr = symbolName + " -> " + ToolUtils.formatAddress(symbol.getAddress());
                    allImports.add(importStr);
                }
                
                StringBuilder output = new StringBuilder();
                for (String entry : allImports) {
                    output.append(entry).append("\n");
                }
                return ToolUtils.persistLargeOutput(context, "imports", output.toString(), allImports.size());
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list imports: " + e.getMessage(), e);
            }
        });
    }
}
