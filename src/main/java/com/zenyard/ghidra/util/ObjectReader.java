package com.zenyard.ghidra.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.zenyard.ghidra.util.ObjectGraph.Symbol;
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
 * <p>
 * All initialized memory blocks are enumerated for globals regardless of section name or
 * permission bits. This covers firmware images that use RWX sections or that have no
 * permission model (flat binaries, RTOS images). Each defined {@link Data} item qualifies
 * as a global when it is either (a) unnamed/auto-generated and referenced from a function,
 * or (b) user-named and not an auto-generated string literal.
 * </p>
 * <p>
 * Auto-named string literals are excluded: their content is self-documenting and they
 * would otherwise dominate the upload set without contributing inference value. Mirrors
 * the IDA-side filter at {@code decompai_ida.objects._all_global_variable_symbols_sync}.
 * </p>
 */
public class ObjectReader {

    /**
     * True when the address has no listing {@link Data} and no incoming references — a true hole.
     * Used to classify emptiness; it does not exclude {@code DAT_*} or other defined globals.
     */
    public static boolean isEmptyNonReferencedHole(Program program, Address address) {
        if (address == null) {
            return false;
        }
        Listing listing = program.getListing();
        if (listing.getDataAt(address) != null || listing.getDataContaining(address) != null) {
            return false;
        }
        return !hasIncomingReferences(program, address);
    }

    private static boolean hasIncomingReferences(Program program, Address address) {
        ReferenceManager refManager = program.getReferenceManager();
        for (Reference ref : refManager.getReferencesTo(address)) {
            return true;
        }
        return false;
    }

    /**
     * True when {@code address} has at least one incoming reference whose source is either
     * inside a function (code xref) or inside a defined data item (data-to-data xref).
     * References from undefined bytes or external space are not counted.
     */
    private static boolean isReferencedFromCodeOrData(Program program, Address address) {
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        Listing listing = program.getListing();
        for (Reference ref : refManager.getReferencesTo(address)) {
            Address from = ref.getFromAddress();
            if (funcManager.getFunctionContaining(from) != null) {
                return true;
            }
            if (listing.getDataContaining(from) != null) {
                return true;
            }
        }
        return false;
    }

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

        // Sections: enumerated via SectionSerializer so detection here stays aligned with
        // what the upload path actually serializes (Program Tree fragments, with a memory
        // block fallback).
        for (SectionSerializer.SectionView view : SectionSerializer.enumerateSections(program)) {
            symbols.add(new Symbol(view.start(), "section"));
        }

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

        if (SectionSerializer.findSectionAt(program, address).isPresent()) {
            return Optional.of(new Symbol(address, "section"));
        }

        return Optional.empty();
    }

    /**
     * Enumerate globals in this block. Skip non-loaded address spaces (OTHER_SPACE blocks
     * like {@code _elfSectionHeaders}, {@code .shstrtab}, {@code .strtab}, ...). These blocks
     * sit at synthetic addresses (commonly 0x0) and any data items the global heuristic flags
     * inside them collide on the server's
     * {@code objects (binary_id, address, min_revision)} primary key when more than one
     * OTHER_SPACE block contributes a global in the same revision.
     */
    static boolean shouldEnumerateMemoryBlockForGlobals(MemoryBlock block) {
        if (block == null) {
            return false;
        }
        return block.getStart().getAddressSpace().isLoadedMemorySpace();
    }

    /**
     * Get all global variable symbols.
     */
    private static List<Symbol> getGlobalVariableSymbols(Program program) {
        List<Symbol> symbols = new ArrayList<>();
        Listing listing = program.getListing();
        FunctionManager funcManager = program.getFunctionManager();
        SymbolTable symbolTable = program.getSymbolTable();

        // Iterate through all memory blocks
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!shouldEnumerateMemoryBlockForGlobals(block)) {
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

                if (funcManager.getFunctionAt(currentAddress) != null) {
                    currentAddress = data.getMaxAddress().next();
                    continue;
                }

                boolean isGlobalVariable = isReferencedFromCodeOrData(program, currentAddress);

                if (isGlobalVariable && !isAutoNamedStringLiteral(
                        data, symbolTable.getPrimarySymbol(currentAddress))) {
                    symbols.add(new Symbol(currentAddress, "global_variable"));
                }

                // Move to next data item
                currentAddress = data.getMaxAddress().next();
            }
        }

        return symbols;
    }

    /**
     * True when {@code data} is an auto-named string literal — content the disassembler has
     * already labeled with its default prefix (e.g. {@code s_Hello_004012a8}). Such items are
     * self-documenting and inference adds no value, so they are dropped from the upload set
     * to keep object counts focused on items that actually need naming or typing.
     */
    static boolean isAutoNamedStringLiteral(Data data, ghidra.program.model.symbol.Symbol symbol) {
        if (data == null || !data.hasStringValue()) {
            return false;
        }
        return symbol == null || symbol.getSource() == SourceType.DEFAULT;
    }

    private static Address getGlobalVariableAddress(Program program, Address address) {
        Listing listing = program.getListing();
        Data data = listing.getDataContaining(address);
        if (data == null) {
            return null;
        }

        Address dataAddress = data.getAddress();
        FunctionManager funcManager = program.getFunctionManager();

        if (funcManager.getFunctionAt(dataAddress) != null) {
            return null;
        }

        if (!isReferencedFromCodeOrData(program, dataAddress)) {
            return null;
        }

        if (isAutoNamedStringLiteral(
                data, program.getSymbolTable().getPrimarySymbol(dataAddress))) {
            return null;
        }

        return dataAddress;
    }
}
