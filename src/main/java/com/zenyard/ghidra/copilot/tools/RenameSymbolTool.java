package com.zenyard.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Tool to rename a symbol (function or global variable).
 */
public class RenameSymbolTool {
    
    private final CopilotToolContext context;
    
    public RenameSymbolTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Renames a symbol such as a function or a global variable")
    public void renameSymbol(String symbolAddress, String newName) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("symbol_address", symbolAddress);
        args.put("new_name", newName);
        ToolUtils.executeTool(context, "rename_symbol", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Address address = ToolUtils.parseAddress(program, symbolAddress);
                if (address == null) {
                    throw new ToolExecutionException("Failed to parse address: " + symbolAddress);
                }

                SymbolTable symbolTable = program.getSymbolTable();
                Symbol symbol = symbolTable.getPrimarySymbol(address);

                if (symbol == null) {
                    throw new ToolExecutionException("No symbol found at address: " + symbolAddress);
                }

                // Use transaction for program modification
                int transactionId = program.startTransaction("Zenyard: Rename symbol");
                try {
                    // In Ghidra 12.0, just use setName() directly instead of remove/create
                    symbol.setName(newName, symbol.getSource());
                } finally {
                    program.endTransaction(transactionId, true);
                }
                return null;
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to rename symbol: " + e.getMessage(), e);
            }
        });
    }
}

