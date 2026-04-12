package com.zenyard.ghidra.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.zenyard.ghidra.api.generated.model.AddressDetail;
import com.zenyard.ghidra.api.generated.model.DecompilerNote;
import com.zenyard.ghidra.api.generated.model.Function;
import com.zenyard.ghidra.api.generated.model.GlobalVariable;
import com.zenyard.ghidra.api.generated.model.LineRange;
import com.zenyard.ghidra.api.generated.model.LVarDetail;
import com.zenyard.ghidra.api.generated.model.Range;
import com.zenyard.ghidra.api.generated.model.RangeDetail;
import com.zenyard.ghidra.api.generated.model.Thunk;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
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
 * NOTE: mirrors zenyard_ida/objects.py read_object_sync() logic
 */
public class FunctionSerializer {
    
    private static final int MAX_INSTRUCTIONS_TO_DECOMPILE = 0x20000;
    private static final Pattern MANGLED_NAME_CLEANUP_REGEX = Pattern.compile("^(?:j_)+|(?:_\\d+)+$");
    /** Ghidra default labels: DAT_<hex> globals, FUN_<hex> functions — used for addr fallback when min-address is ambiguous. */
    private static final Pattern GHIDRA_HEX_DAT_LABEL = Pattern.compile("^DAT_([0-9a-fA-F]+)$");
    private static final Pattern GHIDRA_HEX_FUN_LABEL = Pattern.compile("^FUN_([0-9a-fA-F]+)$");
    
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
        String apiAddress = com.zenyard.ghidra.api.AddressHelper.fromAddress(entryPoint);
        
        // Get function name
        String name = function.getName();
        if (name == null || name.isEmpty()) {
            name = "sub_" + entryPoint.toString();
        }
        
        // Check if name is user-defined (has known name)
        boolean hasKnownName = function.getSymbol().getSource() 
            != ghidra.program.model.symbol.SourceType.DEFAULT;
        
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
                    throw new RuntimeException("Failed to decompile function: " 
                        + (results.getErrorMessage() != null ? results.getErrorMessage() : "Unknown error"));
                }
                
                CodeAndRanges car = extractCodeAndRanges(results, program);
                decompiledCode = car.code();
                ranges = car.ranges();

                long lvarCount = ranges.stream()
                    .filter(r -> r.getDetail() != null && r.getDetail().getActualInstance() instanceof LVarDetail)
                    .count();
                long addrCount = ranges.size() - lvarCount;
                ghidra.util.Msg.debug(FunctionSerializer.class,
                    "Ranges for " + apiAddress + ": " + ranges.size()
                    + " [lvar=" + lvarCount + " addr=" + addrCount + "]");
                
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
        String apiAddress = com.zenyard.ghidra.api.AddressHelper.fromAddress(entryPoint);
        
        String name = thunk.getName();
        if (name == null || name.isEmpty()) {
            name = "thunk_" + entryPoint.toString();
        }
        
        // Get thunk target
        Address[] thunkTargets = thunk.getFunctionThunkAddresses();
        if (thunkTargets == null || thunkTargets.length == 0) {
            throw new RuntimeException("Thunk has no target");
        }
        String targetAddress = com.zenyard.ghidra.api.AddressHelper.fromAddress(thunkTargets[0]);
        
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
        String apiAddress = com.zenyard.ghidra.api.AddressHelper.fromAddress(address);
        
        String name = program.getSymbolTable().getPrimarySymbol(address).getName();
        if (name == null || name.isEmpty()) {
            name = "data_" + address.toString();
        }
        
        boolean hasKnownName = program.getSymbolTable().getPrimarySymbol(address).getSource() 
            != ghidra.program.model.symbol.SourceType.DEFAULT;
        
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
        globalVar.setUses(uses.stream().map(addr -> com.zenyard.ghidra.api.AddressHelper.fromAddress(addr))
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
    
    record CodeAndRanges(String code, List<Range> ranges) {}

    record TokenData(String text, RangeDetail detail) {}

    private static CodeAndRanges extractCodeAndRanges(DecompileResults results, Program program) {
        ClangTokenGroup markup = results.getCCodeMarkup();
        List<TokenData> tokenData = new ArrayList<>();

        Iterator<ClangToken> it = markup.tokenIterator(true);
        while (it.hasNext()) {
            ClangToken token = it.next();
            tokenData.add(new TokenData(token.getText(), buildRangeDetail(token, program)));
        }

        return buildCodeAndRanges(tokenData);
    }

    static CodeAndRanges buildCodeAndRanges(List<TokenData> tokens) {
        StringBuilder code = new StringBuilder();
        List<Range> ranges = new ArrayList<>();

        for (TokenData token : tokens) {
            String text = token.text();
            if (text == null || text.isEmpty()) continue;

            int start = code.length();
            code.append(text);

            if (token.detail() != null) {
                Range range = new Range();
                range.setStart(start);
                range.setLength(text.length());
                range.setDetail(token.detail());
                ranges.add(range);
            }
        }

        return new CodeAndRanges(code.toString(), ranges);
    }

    /**
     * Resolves {@link RangeDetail} for a decompiler token.
     * <p>
     * Mirrors IDA's {@code _detail_from_ctree_item} + {@code _narrow_range} approach:
     * only <b>variable tokens</b> and <b>function-name tokens</b> produce ranges.
     * Operators ({@code =}, {@code !=}, {@code *}, {@code +}), keywords
     * ({@code if}, {@code return}, {@code while}), syntax ({@code (}, {@code ,}),
     * types, comments, and labels are all silently dropped.
     * <ul>
     *   <li>{@link ClangVariableToken} → {@link LVarDetail} for locals/args,
     *       {@link AddressDetail} for globals ({@link HighGlobal} or {@code DAT_…}).</li>
     *   <li>{@link ClangFuncNameToken} → {@link AddressDetail} for the callee's entry
     *       point. Library/external functions are excluded.</li>
     * </ul>
     */
    private static RangeDetail buildRangeDetail(ClangToken token, Program program) {
        if (token instanceof ClangVariableToken) {
            return buildVariableTokenRange(token, program);
        }
        if (token instanceof ClangFuncNameToken) {
            return buildFuncCallRange((ClangFuncNameToken) token, program);
        }
        return null;
    }

    /**
     * Range for a {@link ClangVariableToken}: locals/args → {@link LVarDetail},
     * globals → {@link AddressDetail}.
     */
    private static RangeDetail buildVariableTokenRange(ClangToken token, Program program) {
        HighVariable highVar = token.getHighVariable();
        if (highVar == null) {
            return null;
        }
        String name = highVar.getName();
        if (name == null || name.isEmpty()) {
            return null;
        }

        if (highVar instanceof HighGlobal) {
            Address globalAddr = globalAddressFromHighGlobal((HighGlobal) highVar);
            if (globalAddr != null) {
                return buildAddressDetailRange(globalAddr);
            }
            return null;
        }

        if (highVar instanceof HighLocal) {
            if (isGhidraGlobalDataStyleName(name)) {
                Address dataAddr = addressFromParsedHexLabel(program, name);
                if (dataAddr != null) {
                    return buildAddressDetailRange(dataAddr);
                }
            }
            LVarDetail lvar = new LVarDetail();
            lvar.setName(name);
            lvar.setIsArg(highVar instanceof HighParam);
            RangeDetail detail = new RangeDetail();
            detail.setActualInstance(lvar);
            return detail;
        }

        return null;
    }

    /**
     * Range for a {@link ClangFuncNameToken}: resolves the callee's entry point.
     * Returns {@code null} for library/external functions (thunks to externals)
     * and for the function's own declaration name (where no pcode CALL op exists).
     */
    private static RangeDetail buildFuncCallRange(ClangFuncNameToken token, Program program) {
        Address minAddr = token.getMinAddress();
        if (minAddr == null) {
            return null;
        }
        FunctionManager fm = program.getFunctionManager();
        ReferenceManager rm = program.getReferenceManager();

        Reference[] refs = rm.getReferencesFrom(minAddr);
        for (Reference ref : refs) {
            if (ref.getReferenceType().isCall()) {
                Address to = ref.getToAddress();
                ghidra.program.model.listing.Function callee = fm.getFunctionAt(to);
                if (callee == null) {
                    callee = fm.getFunctionContaining(to);
                }
                if (callee != null) {
                    if (isLibraryFunction(callee)) {
                        return null;
                    }
                    return buildAddressDetailRange(callee.getEntryPoint());
                }
            }
        }

        String text = token.getText();
        if (text != null) {
            Matcher m = GHIDRA_HEX_FUN_LABEL.matcher(text.trim());
            if (m.matches()) {
                Address funAddr = defaultSpaceAddressFromHex(program, m.group(1));
                if (funAddr != null) {
                    ghidra.program.model.listing.Function f = fm.getFunctionAt(funAddr);
                    if (f != null) {
                        if (isLibraryFunction(f)) {
                            return null;
                        }
                        return buildAddressDetailRange(f.getEntryPoint());
                    }
                }
            }
        }

        return null;
    }

    private static boolean isLibraryFunction(ghidra.program.model.listing.Function func) {
        if (func.isExternal()) {
            return true;
        }
        if (func.isThunk()) {
            ghidra.program.model.listing.Function thunked = func.getThunkedFunction(true);
            return thunked != null && thunked.isExternal();
        }
        return false;
    }

    private static boolean isGhidraGlobalDataStyleName(String name) {
        return name.regionMatches(true, 0, "DAT_", 0, 4);
    }

    private static Address addressFromParsedHexLabel(Program program, String label) {
        if (label == null) {
            return null;
        }
        String t = label.trim();
        Matcher m = GHIDRA_HEX_DAT_LABEL.matcher(t);
        if (m.matches()) {
            return defaultSpaceAddressFromHex(program, m.group(1));
        }
        return null;
    }

    private static Address defaultSpaceAddressFromHex(Program program, String hexDigits) {
        try {
            long offset = Long.parseUnsignedLong(hexDigits, 16);
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            return space.getAddress(offset);
        } catch (Exception e) {
            return null;
        }
    }

    private static Address globalAddressFromHighGlobal(HighGlobal hg) {
        Varnode rep = hg.getRepresentative();
        return rep != null ? rep.getAddress() : null;
    }

    private static RangeDetail buildAddressDetailRange(Address programAddress) {
        AddressDetail addrDetail = new AddressDetail();
        addrDetail.setAddress(com.zenyard.ghidra.api.AddressHelper.fromAddress(programAddress));
        RangeDetail detail = new RangeDetail();
        detail.setActualInstance(addrDetail);
        return detail;
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
                        String apiAddr = com.zenyard.ghidra.api.AddressHelper.fromAddress(targetFunc.getEntryPoint());
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
                if (targetFunc != null 
                    && targetFunc.getEntryPoint().equals(targetAddr) 
                    && !targetFunc.equals(function)) {
                    String apiAddr = com.zenyard.ghidra.api.AddressHelper.fromAddress(targetFunc.getEntryPoint());
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
                    String apiAddr = com.zenyard.ghidra.api.AddressHelper.fromAddress(targetAddr);
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

