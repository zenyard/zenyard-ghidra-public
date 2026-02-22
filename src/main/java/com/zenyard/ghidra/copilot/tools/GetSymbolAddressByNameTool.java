package com.zenyard.ghidra.copilot.tools;

import java.util.List;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Tool to get address of a symbol (function or global variable) by name.
 */
public class GetSymbolAddressByNameTool {
    
    private final CopilotToolContext context;
    
    public GetSymbolAddressByNameTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Resolve a symbol name to its address. Supports direct symbol names and demangled-name fallback lookup.")
    public String getSymbolAddressByName(
            @P("Symbol name to resolve (function/global/label name, mangled or demangled).") String symbolName) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("symbol_name", symbolName);
        return ToolUtils.executeTool(context, "get_symbol_address_by_name", args, () -> {
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
                    // Fallback: user may have passed a demangled name while the table has mangled names
                    Symbol matched = resolveByDemangledName(symbolTable, program, symbolName);
                    if (matched != null) {
                        return ToolUtils.formatAddress(matched.getAddress());
                    }
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
        });
    }

    /**
     * Fallback when direct lookup fails: iterate defined symbols, demangle each name,
     * and return the first symbol whose demangled name or signature matches the given name.
     */
    private Symbol resolveByDemangledName(SymbolTable symbolTable, Program program, String symbolName) {
        String normalizedInput = DemanglerUtil.stripSuperfluousSignatureSpaces(symbolName);
        SymbolIterator iter = symbolTable.getDefinedSymbols();
        while (iter.hasNext()) {
            context.checkCancelled();
            Symbol symbol = iter.next();
            String name = symbol.getName();
            Address address = symbol.getAddress();
            List<DemangledObject> demangledList = DemanglerUtil.demangle(program, name, address);
            if (demangledList == null || demangledList.isEmpty()) {
                continue;
            }
            DemangledObject demangled = demangledList.get(0);
            String demangledName = demangled.getDemangledName();
            String signature = demangled.getSignature();
            if (demangledName != null && (symbolName.equals(demangledName)
                    || normalizedInput.equals(DemanglerUtil.stripSuperfluousSignatureSpaces(demangledName)))) {
                return symbol;
            }
            if (signature != null && (symbolName.equals(signature)
                    || normalizedInput.equals(DemanglerUtil.stripSuperfluousSignatureSpaces(signature)))) {
                return symbol;
            }
        }
        return null;
    }
}

