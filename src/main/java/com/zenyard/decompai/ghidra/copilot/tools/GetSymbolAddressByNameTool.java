package com.zenyard.decompai.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Tool to get address of a symbol (function or global variable) by name.
 */
public class GetSymbolAddressByNameTool {
    
    private final CopilotToolContext context;
    
    public GetSymbolAddressByNameTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Get address of function or global variable given its name")
    public String getSymbolAddressByName(String symbolName) {
        try {
            context.checkCancelled();
            
            Program program = context.getProgram();
            if (program == null) {
                throw new ToolExecutionException("No program is currently loaded");
            }
            
            SymbolTable symbolTable = program.getSymbolTable();
            // getSymbols returns an iterator of symbols with the given name
            java.util.Iterator<Symbol> symbolsIter = symbolTable.getSymbols(symbolName);
            if (!symbolsIter.hasNext()) {
                // TODO: Handle mangled names
                throw new ToolExecutionException("Failed to resolve symbol to address: " + symbolName);
            }
            
            // Get the first symbol (primary symbol)
            Symbol symbol = symbolsIter.next();
            Address address = symbol.getAddress();
            return ToolUtils.formatAddress(address);
        } catch (ToolExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new ToolExecutionException("Failed to get symbol address: " + e.getMessage(), e);
        }
    }
}

