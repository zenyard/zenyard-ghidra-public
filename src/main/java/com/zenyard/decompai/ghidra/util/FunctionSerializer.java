package com.zenyard.decompai.ghidra.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import com.zenyard.decompai.ghidra.api.generated.model.DecompilerNote;
import com.zenyard.decompai.ghidra.api.generated.model.Function;
import com.zenyard.decompai.ghidra.api.generated.model.GlobalVariable;
import com.zenyard.decompai.ghidra.api.generated.model.LineRange;
import com.zenyard.decompai.ghidra.api.generated.model.Range;
import com.zenyard.decompai.ghidra.api.generated.model.Thunk;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

/**
 * Utility class for serializing Ghidra Function to API Object model.
 * 
 * NOTE: mirrors decompai_ida/objects.py read_object_sync() logic
 */
public class FunctionSerializer {
    
    private static final int MAX_INSTRUCTIONS_TO_DECOMPILE = 0x20000;
    private static final Pattern MANGLED_NAME_CLEANUP_REGEX = Pattern.compile("^(?:j_)+|(?:_\\d+)+$");
    
    /**
     * Serialize a function to API Function model.
     * 
     * @param program The program containing the function
     * @param function The function to serialize
     * @param inferenceSeqNumber Inference sequence number (optional, default 0)
     * @return Function object ready for API
     */
    public static Function serializeFunction(Program program, ghidra.program.model.listing.Function function, 
                                            int inferenceSeqNumber) {
        if (program == null || function == null) {
            throw new IllegalArgumentException("Program and function cannot be null");
        }
        
        // Check if function is too large
        int instructionCount = countInstructions(function);
        if (instructionCount >= MAX_INSTRUCTIONS_TO_DECOMPILE) {
            throw new RuntimeException("Function too large to decompile: " + instructionCount + " instructions");
        }
        
        // Get function address
        ghidra.program.model.address.Address entryPoint = function.getEntryPoint();
        String apiAddress = com.zenyard.decompai.ghidra.api.AddressHelper.fromAddress(entryPoint);
        
        // Get function name
        String name = function.getName();
        if (name == null || name.isEmpty()) {
            name = "sub_" + entryPoint.toString();
        }
        
        // Check if name is user-defined (has known name)
        boolean hasKnownName = function.getSymbol().getSource() != 
            ghidra.program.model.symbol.SourceType.DEFAULT;
        
        // Get mangled name (cleaned)
        String mangledName = null;
        if (hasKnownName) {
            String fullName = function.getSymbol().getName();
            mangledName = cleanMangledName(fullName);
            if (mangledName.equals(name)) {
                mangledName = null; // Don't duplicate if same as name
            }
        }
        
        // Decompile function
        String decompiledCode;
        List<Range> ranges;
        List<LineRange> lineRanges;
        List<DecompilerNote> decompilerNotes;
        
        try {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(program);
            
            try {
                DecompileOptions options = new DecompileOptions();
                decompiler.setOptions(options);
                
                DecompileResults results = decompiler.decompileFunction(
                    function, 
                    30, 
                    TaskMonitor.DUMMY
                );
                
                if (!results.decompileCompleted()) {
                    throw new RuntimeException("Failed to decompile function: " + 
                        (results.getErrorMessage() != null ? results.getErrorMessage() : "Unknown error"));
                }
                
                decompiledCode = results.getDecompiledFunction().getC();
                
                // Extract ranges from decompiled code
                ranges = extractRanges(program, function, results);
                
                // Extract line ranges (simplified - one range per line)
                lineRanges = extractLineRanges(decompiledCode);
                
                // Extract decompiler notes/warnings
                decompilerNotes = extractDecompilerNotes(results);
                
            } finally {
                decompiler.closeProgram();
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to decompile function: " + e.getMessage(), e);
        }
        
        // Get function calls
        List<String> calls = getCalls(program, function);
        
        // Get data references
        List<String> dataRefsTo = getDataRefsTo(program, function);
        
        Function func = new Function();
        func.setAddress(apiAddress);
        func.setName(name);
        func.setHasKnownName(hasKnownName);
        func.setInferenceSeqNumber(inferenceSeqNumber);
        func.setCode(decompiledCode);
        func.setCalls(calls);
        func.setDataRefsTo(dataRefsTo);
        func.setMangledName(mangledName);
        func.setRanges(ranges);
        func.setLineRanges(lineRanges);
        func.setDecompilerNotes(decompilerNotes);
        return func;
    }
    
    /**
     * Serialize a thunk function.
     */
    public static Thunk serializeThunk(Program program, ghidra.program.model.listing.Function thunk, 
                                       int inferenceSeqNumber) {
        ghidra.program.model.address.Address entryPoint = thunk.getEntryPoint();
        String apiAddress = com.zenyard.decompai.ghidra.api.AddressHelper.fromAddress(entryPoint);
        
        String name = thunk.getName();
        if (name == null || name.isEmpty()) {
            name = "thunk_" + entryPoint.toString();
        }
        
        // Get thunk target
        Address[] thunkTargets = thunk.getFunctionThunkAddresses();
        if (thunkTargets == null || thunkTargets.length == 0) {
            throw new RuntimeException("Thunk has no target");
        }
        String targetAddress = com.zenyard.decompai.ghidra.api.AddressHelper.fromAddress(thunkTargets[0]);
        
        Thunk apiThunk = new Thunk();
        apiThunk.setAddress(apiAddress);
        apiThunk.setName(name);
        apiThunk.setHasKnownName(false);
        apiThunk.setInferenceSeqNumber(inferenceSeqNumber);
        apiThunk.setTarget(targetAddress);
        return apiThunk;
    }
    
    /**
     * Serialize a global variable.
     */
    public static GlobalVariable serializeGlobalVariable(Program program, ghidra.program.model.address.Address address, 
                                                         int inferenceSeqNumber) {
        String apiAddress = com.zenyard.decompai.ghidra.api.AddressHelper.fromAddress(address);
        
        String name = program.getSymbolTable().getPrimarySymbol(address).getName();
        if (name == null || name.isEmpty()) {
            name = "data_" + address.toString();
        }
        
        boolean hasKnownName = program.getSymbolTable().getPrimarySymbol(address).getSource() != 
            ghidra.program.model.symbol.SourceType.DEFAULT;
        
        String mangledName = null;
        if (hasKnownName) {
            String fullName = program.getSymbolTable().getPrimarySymbol(address).getName();
            mangledName = cleanMangledName(fullName);
            if (mangledName.equals(name)) {
                mangledName = null;
            }
        }
        
        // Get uses (functions that reference this variable)
        List<ghidra.program.model.address.Address> uses = getUses(program, address);
        
        GlobalVariable globalVar = new GlobalVariable();
        globalVar.setAddress(apiAddress);
        globalVar.setName(name);
        globalVar.setHasKnownName(hasKnownName);
        globalVar.setInferenceSeqNumber(inferenceSeqNumber);
        globalVar.setUses(uses.stream().map(addr -> com.zenyard.decompai.ghidra.api.AddressHelper.fromAddress(addr))
            .collect(java.util.stream.Collectors.toList()));
        globalVar.setMangledName(mangledName);
        return globalVar;
    }
    
    /**
     * Count instructions in a function.
     */
    private static int countInstructions(ghidra.program.model.listing.Function function) {
        int count = 0;
        AddressSet body = new AddressSet(function.getBody());
        for (Address addr : body.getAddresses(true)) {
            Instruction instruction = function.getProgram().getListing().getInstructionAt(addr);
            if (instruction != null) {
                count++;
                if (count >= MAX_INSTRUCTIONS_TO_DECOMPILE) {
                    break;
                }
            }
        }
        return count;
    }
    
    /**
     * Clean mangled name by removing common prefixes and suffixes.
     */
    private static String cleanMangledName(String name) {
        if (name == null) {
            return null;
        }
        return MANGLED_NAME_CLEANUP_REGEX.matcher(name).replaceAll("");
    }
    
    /**
     * Extract ranges from decompiled code.
     * This is a simplified version - in a full implementation, we'd parse the HighFunction
     * to get accurate ranges for addresses and local variables.
     */
    private static List<Range> extractRanges(Program program, ghidra.program.model.listing.Function function,
                                            DecompileResults results) {
        List<Range> ranges = new ArrayList<>();
        
        // For now, we'll create a basic implementation that finds addresses in the code
        // A full implementation would use HighFunction to get accurate ranges
        // This is a placeholder - real implementation would use HighFunction.getLocalSymbolMap()
        // and HighFunction.getGlobalSymbolMap() to get accurate ranges
        
        return ranges;
    }
    
    /**
     * Extract line ranges from decompiled code.
     */
    private static List<LineRange> extractLineRanges(String code) {
        List<LineRange> lineRanges = new ArrayList<>();
        String[] lines = code.split("\n");
        
        for (int i = 0; i < lines.length; i++) {
            String lineId = "line_" + (i + 1);
            LineRange lineRange = new LineRange();
            lineRange.setLineCount(1);
            lineRange.setId(lineId);
            lineRanges.add(lineRange);
        }
        
        return lineRanges;
    }
    
    /**
     * Extract decompiler notes/warnings.
     */
    private static List<DecompilerNote> extractDecompilerNotes(DecompileResults results) {
        List<DecompilerNote> notes = new ArrayList<>();
        
        // Ghidra's decompiler doesn't expose warnings the same way IDA does
        // This is a placeholder - we can enhance this later if needed
        
        return notes;
    }
    
    /**
     * Get function calls from a function.
     */
    private static List<String> getCalls(Program program, ghidra.program.model.listing.Function function) {
        List<String> calls = new ArrayList<>();
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        
        AddressSet body = new AddressSet(function.getBody());
        for (ghidra.program.model.address.Address addr : body.getAddresses(true)) {
            Instruction instruction = program.getListing().getInstructionAt(addr);
            if (instruction == null) {
                continue;
            }
            
            // Get flow references (calls)
            Reference[] flowRefs = refManager.getFlowReferencesFrom(addr);
            for (Reference ref : flowRefs) {
                // In Ghidra 12.0, use getReferenceType() instead of getFlowType()
                if (ref.getReferenceType().isCall()) {
                    ghidra.program.model.address.Address targetAddr = ref.getToAddress();
                    ghidra.program.model.listing.Function targetFunc = funcManager.getFunctionAt(targetAddr);
                    if (targetFunc != null && !targetFunc.equals(function)) {
                        String apiAddr = com.zenyard.decompai.ghidra.api.AddressHelper.fromAddress(targetFunc.getEntryPoint());
                        if (!calls.contains(apiAddr)) {
                            calls.add(apiAddr);
                        }
                    }
                }
            }
            
            // Also check data references to function entry points
            Reference[] dataRefs = refManager.getReferencesFrom(addr);
            for (Reference ref : dataRefs) {
                ghidra.program.model.address.Address targetAddr = ref.getToAddress();
                ghidra.program.model.listing.Function targetFunc = funcManager.getFunctionAt(targetAddr);
                if (targetFunc != null && 
                    targetFunc.getEntryPoint().equals(targetAddr) && 
                    !targetFunc.equals(function)) {
                    String apiAddr = com.zenyard.decompai.ghidra.api.AddressHelper.fromAddress(targetFunc.getEntryPoint());
                    if (!calls.contains(apiAddr)) {
                        calls.add(apiAddr);
                    }
                }
            }
        }
        
        return calls;
    }
    
    /**
     * Get data references from a function.
     */
    private static List<String> getDataRefsTo(Program program, ghidra.program.model.listing.Function function) {
        List<String> dataRefs = new ArrayList<>();
        ReferenceManager refManager = program.getReferenceManager();
        
        AddressSet body = new AddressSet(function.getBody());
        for (ghidra.program.model.address.Address addr : body.getAddresses(true)) {
            Reference[] refs = refManager.getReferencesFrom(addr);
            for (Reference ref : refs) {
                // In Ghidra 12.0, use getReferenceType() instead of getFlowType()
                ghidra.program.model.symbol.RefType refType = ref.getReferenceType();
                if (!refType.isCall() && !refType.isJump()) {
                    ghidra.program.model.address.Address targetAddr = ref.getToAddress();
                    String apiAddr = com.zenyard.decompai.ghidra.api.AddressHelper.fromAddress(targetAddr);
                    if (!dataRefs.contains(apiAddr)) {
                        dataRefs.add(apiAddr);
                    }
                }
            }
        }
        
        return dataRefs;
    }
    
    /**
     * Get uses of a global variable (functions that reference it).
     */
    private static List<ghidra.program.model.address.Address> getUses(Program program, ghidra.program.model.address.Address variableAddress) {
        List<ghidra.program.model.address.Address> uses = new ArrayList<>();
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        
        ghidra.program.model.symbol.ReferenceIterator refsToIter = refManager.getReferencesTo(variableAddress);
        while (refsToIter.hasNext()) {
            Reference ref = refsToIter.next();
            ghidra.program.model.listing.Function func = funcManager.getFunctionContaining(ref.getFromAddress());
            if (func != null) {
                ghidra.program.model.address.Address apiAddr = func.getEntryPoint();
                if (!uses.contains(apiAddr)) {
                    uses.add(apiAddr);
                }
            }
        }
        
        return uses;
    }
}

