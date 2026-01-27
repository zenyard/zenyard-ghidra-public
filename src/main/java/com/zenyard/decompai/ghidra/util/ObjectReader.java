package com.zenyard.decompai.ghidra.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.zenyard.decompai.ghidra.util.ObjectGraph.Symbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Utility for reading all object symbols (functions and global variables).
 * 
 * Mirrors decompai_ida/objects.py all_object_symbols_sync() logic.
 */
public class ObjectReader {
    
    /**
     * Get all object symbols (functions and global variables) in the program.
     * 
     * @param program The program
     * @return List of symbols (functions and global variables)
     */
    public static List<Symbol> getAllObjectSymbols(Program program) {
        List<Symbol> symbols = new ArrayList<>();
        
        // Get all functions
        FunctionManager funcManager = program.getFunctionManager();
        for (Function function : funcManager.getFunctions(true)) {
            // Skip thunks for now (can be added later)
            if (function.isThunk()) {
                continue;
            }
            
            symbols.add(new Symbol(function.getEntryPoint(), "function"));
        }
        
        // Get all global variables
        // Include:
        // 1. Unnamed global variables that are referenced from code
        // 2. Named global variables (excluding auto-generated string literals)
        symbols.addAll(getGlobalVariableSymbols(program));
        
        return symbols;
    }

    /**
     * Get object symbol for a specific address, if the address belongs to a function
     * or a global variable.
     */
    public static Optional<Symbol> getObjectSymbolForAddress(Program program, Address address) {
        if (address == null) {
            return Optional.empty();
        }

        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionContaining(address);
        if (function != null && !function.isThunk()) {
            return Optional.of(new Symbol(function.getEntryPoint(), "function"));
        }

        Address globalVarAddress = getGlobalVariableAddress(program, address);
        if (globalVarAddress != null) {
            return Optional.of(new Symbol(globalVarAddress, "global_variable"));
        }

        return Optional.empty();
    }
    
    /**
     * Get all global variable symbols.
     */
    private static List<Symbol> getGlobalVariableSymbols(Program program) {
        List<Symbol> symbols = new ArrayList<>();
        Listing listing = program.getListing();
        SymbolTable symbolTable = program.getSymbolTable();
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        
        // Iterate through all memory blocks
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }
            
            Address currentAddress = block.getStart();
            Address endAddress = block.getEnd();
            
            while (currentAddress != null && currentAddress.compareTo(endAddress) <= 0) {
                Data data = listing.getDataAt(currentAddress);
                if (data == null) {
                    currentAddress = currentAddress.next();
                    continue;
                }
                
                ghidra.program.model.symbol.Symbol symbol = symbolTable.getPrimarySymbol(currentAddress);
                String name = symbol != null ? symbol.getName() : null;
                
                // Check if this is a global variable
                boolean isGlobalVariable = false;
                
                // Include unnamed global variables that are referenced from code
                if (name == null || symbol == null || symbol.getSource() == SourceType.DEFAULT) {
                    // Check if it's referenced from code
                    boolean referencedFromCode = false;
                    for (Reference ref : refManager.getReferencesTo(currentAddress)) {
                        Function accessingFunction = funcManager.getFunctionContaining(ref.getFromAddress());
                        if (accessingFunction != null) {
                            referencedFromCode = true;
                            break;
                        }
                    }
                    
                    if (referencedFromCode) {
                        isGlobalVariable = true;
                    }
                } else {
                    // Include named global variables, excluding auto-generated string literals
                    // TODO: Check for string literal flags more precisely
                    // For now, we'll include all named symbols that aren't functions
                    if (funcManager.getFunctionAt(currentAddress) == null) {
                    // Not a function, could be a global variable
                    // Exclude if it looks like an auto-generated string (starts with "a" and is a string)
                    // Note: Ghidra's Data doesn't have isString() - we'll check data type instead
                    boolean isAutoString = name.startsWith("a") 
                        && data.getDataType().getDisplayName().contains("string") 
                        && symbol.getSource() == SourceType.DEFAULT;
                        
                        if (!isAutoString) {
                            isGlobalVariable = true;
                        }
                    }
                }
                
                if (isGlobalVariable) {
                    symbols.add(new Symbol(currentAddress, "global_variable"));
                }
                
                // Move to next data item
                currentAddress = data.getMaxAddress().next();
            }
        }
        
        return symbols;
    }

    private static Address getGlobalVariableAddress(Program program, Address address) {
        Listing listing = program.getListing();
        Data data = listing.getDataContaining(address);
        if (data == null) {
            return null;
        }

        Address dataAddress = data.getAddress();
        SymbolTable symbolTable = program.getSymbolTable();
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();

        if (funcManager.getFunctionAt(dataAddress) != null) {
            return null;
        }

        ghidra.program.model.symbol.Symbol symbol = symbolTable.getPrimarySymbol(dataAddress);
        String name = symbol != null ? symbol.getName() : null;

        if (name == null || symbol == null || symbol.getSource() == SourceType.DEFAULT) {
            for (Reference ref : refManager.getReferencesTo(dataAddress)) {
                Function accessingFunction = funcManager.getFunctionContaining(ref.getFromAddress());
                if (accessingFunction != null) {
                    return dataAddress;
                }
            }
            return null;
        }

        boolean isAutoString = name.startsWith("a") 
            && data.getDataType().getDisplayName().contains("string") 
            && symbol.getSource() == SourceType.DEFAULT;

        return isAutoString ? null : dataAddress;
    }
}

