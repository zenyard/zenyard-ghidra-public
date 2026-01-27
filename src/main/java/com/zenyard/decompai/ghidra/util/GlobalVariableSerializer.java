package com.zenyard.decompai.ghidra.util;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.zenyard.decompai.ghidra.api.AddressHelper;
import com.zenyard.decompai.ghidra.api.generated.model.GlobalVariable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Utility for serializing global variables to API model.
 * 
 * Mirrors decompai_ida/objects.py read_object_sync() logic for global variables.
 */
public class GlobalVariableSerializer {
    
    /**
     * Serialize a global variable to API GlobalVariable model.
     * 
     * @param program The program containing the variable
     * @param address The address of the global variable
     * @param inferenceSeqNumber Inference sequence number (optional, default 0)
     * @return GlobalVariable object ready for API
     */
    public static GlobalVariable serializeGlobalVariable(Program program, Address address, int inferenceSeqNumber) {
        if (program == null || address == null) {
            throw new IllegalArgumentException("Program and address cannot be null");
        }
        
        Listing listing = program.getListing();
        Data data = listing.getDataAt(address);
        
        if (data == null) {
            throw new IllegalArgumentException("No data found at address: " + address);
        }
        
        // Get variable name
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol symbol = symbolTable.getPrimarySymbol(address);
        String name = symbol != null ? symbol.getName() : "data_" + address.toString();
        
        // Check if name is user-defined
        boolean hasKnownName = symbol != null 
            && symbol.getSource() != SourceType.DEFAULT;
        
        // Get mangled name if available
        String mangledName = null;
        if (hasKnownName && symbol != null) {
            mangledName = symbol.getName();
        }
        
        // Get all functions that reference this variable (uses)
        List<String> uses = getAccesses(program, address);
        
        // Create GlobalVariable object
        GlobalVariable gv = new GlobalVariable();
        gv.setAddress(AddressHelper.fromAddress(address));
        gv.setName(name);
        gv.setHasKnownName(hasKnownName);
        gv.setMangledName(mangledName);
        gv.setInferenceSeqNumber(inferenceSeqNumber);
        gv.setUses(uses);
        
        return gv;
    }
    
    /**
     * Get all functions that access (reference) this global variable.
     * 
     * Mirrors decompai_ida/objects.py _get_accesses() logic.
     */
    private static List<String> getAccesses(Program program, Address address) {
        Set<String> uses = new HashSet<>();
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        
        // Get all references to this address
        for (Reference ref : refManager.getReferencesTo(address)) {
            Address fromAddress = ref.getFromAddress();
            Function accessingFunction = funcManager.getFunctionContaining(fromAddress);
            
            if (accessingFunction != null) {
                String funcAddress = AddressHelper.fromAddress(accessingFunction.getEntryPoint());
                uses.add(funcAddress);
            }
        }
        
        return new ArrayList<>(uses);
    }
}

