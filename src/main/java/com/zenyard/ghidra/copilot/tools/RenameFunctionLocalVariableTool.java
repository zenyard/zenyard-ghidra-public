package com.zenyard.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.Varnode;

/**
 * Tool to rename a local variable in a function.
 * 
 * Note: This is a complex operation that requires decompiler API access.
 */
public class RenameFunctionLocalVariableTool {
    
    private final CopilotToolContext context;
    
    public RenameFunctionLocalVariableTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Rename one local variable within a function. Inputs: `address` (function location), `from_name` (existing local variable), and `to_name` (new valid local name).")
    public String renameFunctionLocalVariable(
            @P("Function address (hex like `0x401000`) where the local variable exists.") String address,
            @P("Current local variable name in that function.") String fromName,
            @P("New local variable name to apply.") String toName) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        args.put("from_name", fromName);
        args.put("to_name", toName);
        return ToolUtils.executeTool(context, "rename_function_local_variable", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Function function = ToolUtils.getFunction(program, address);
                if (function == null) {
                    throw new ToolExecutionException("Failed to retrieve function from address: " + address);
                }

                if (!com.zenyard.ghidra.illum.InferenceNameUtils.isValidName(toName)) {
                    throw new ToolExecutionException("Invalid local variable name: " + toName);
                }

                // Use transaction for program modification
                int transactionId = program.startTransaction("Zenyard: Rename local variable");
                boolean committed = false;
                try {
                    // Decompile function to get HighFunction
                    DecompInterface decompiler = new DecompInterface();
                    decompiler.openProgram(program);

                    try {
                        DecompileOptions options = new DecompileOptions();
                        decompiler.setOptions(options);

                        DecompileResults results = decompiler.decompileFunction(
                            function,
                            30, // Timeout in seconds (getDefaultTimeout() removed in Ghidra 12.0)
                            context.getMonitor() != null ? context.getMonitor() : ghidra.util.task.TaskMonitor.DUMMY
                        );

                        if (!results.decompileCompleted()) {
                            throw new ToolExecutionException("Failed to decompile function: "
                                + (results.getErrorMessage() != null ? results.getErrorMessage() : "Unknown error"));
                        }

                        HighFunction highFunction = results.getHighFunction();
                        if (highFunction == null) {
                            throw new ToolExecutionException("No high function available for " + address);
                        }

                        HighSymbol symbol = findSymbolByName(highFunction, fromName);
                        if (symbol == null) {
                            throw new ToolExecutionException(
                                "Variable '" + fromName + "' not found in function at " + address);
                        }

                        HighVariable highVar = symbol.getHighVariable();
                        if (highVar == null) {
                            throw new ToolExecutionException(
                                "No high variable available for '" + fromName + "' in function at " + address);
                        }

                        Varnode storage = highVar.getRepresentative();
                        if (storage == null) {
                            throw new ToolExecutionException(
                                "Variable '" + fromName + "' has no representative storage");
                        }

                        Address storageAddress = storage.getAddress();
                        if (storageAddress.isUniqueAddress()) {
                            throw new ToolExecutionException(
                                "Variable '" + fromName + "' uses unique storage and cannot be renamed");
                        }
                        if (!storageAddress.isStackAddress() && !storageAddress.isRegisterAddress()) {
                            throw new ToolExecutionException(
                                "Variable '" + fromName + "' is not a local variable");
                        }

                        LocalVariable localVar = com.zenyard.ghidra.illum.InferenceNameUtils
                            .findLocalVariableByStorage(function, storage);
                        if (localVar == null) {
                            HighFunctionDBUtil.commitLocalNamesToDatabase(highFunction, SourceType.USER_DEFINED);
                            localVar = com.zenyard.ghidra.illum.InferenceNameUtils
                                .findLocalVariableByStorage(function, storage);
                        }

                        if (localVar == null) {
                            throw new ToolExecutionException(
                                "Unable to resolve local variable for '" + fromName + "' in function at " + address);
                        }

                        localVar.setName(toName, SourceType.USER_DEFINED);
                        committed = true;
                        return String.format(
                            "Renamed local variable '%s' to '%s' in function at %s",
                            fromName, toName, address);

                    } finally {
                        decompiler.closeProgram();
                    }
                } finally {
                    program.endTransaction(transactionId, committed);
                }
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to rename local variable: " + e.getMessage(), e);
            }
        });
    }

    private HighSymbol findSymbolByName(HighFunction highFunction, String variableName) {
        java.util.Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }
}

