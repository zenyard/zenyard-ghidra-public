package com.zenyard.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import javax.swing.SwingUtilities;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Tool to set the type of a local variable in a function.
 */
public class SetLocalVariableTypeTool {
    
    private final CopilotToolContext context;
    
    public SetLocalVariableTypeTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Set a local variable type within one function. Inputs: `function_address` (function location), `variable_name` (existing local variable), and `new_type` (valid Ghidra/C type, e.g. `int`, `char *`, `MyStruct`).")
    public String setLocalVariableType(
            @P("Function address (hex like `0x401000`) that contains the local variable.") String functionAddress,
            @P("Current local variable name exactly as shown in the decompiler for that function.") String variableName,
            @P("New type expression to apply (for example `int`, `char *`, `MyStruct`).") String newType) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("function_address", functionAddress);
        args.put("variable_name", variableName);
        args.put("new_type", newType);
        return ToolUtils.executeTool(context, "set_local_variable_type", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                ghidra.program.model.listing.Function function = ToolUtils.getFunction(program, functionAddress);
                if (function == null) {
                    throw new ToolExecutionException("Failed to retrieve function from address: " + functionAddress);
                }

                // Decompile to get HighFunction
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(program);
                
                try {
                    TaskMonitor monitor = context.getMonitor();
                    DecompileResults results = decompiler.decompileFunction(
                        function,
                        60,
                        monitor != null ? monitor : TaskMonitor.DUMMY
                    );
                    
                    if (!results.decompileCompleted()) {
                        throw new ToolExecutionException("Failed to decompile function: " + results.getErrorMessage());
                    }
                    
                    HighFunction highFunction = results.getHighFunction();
                    if (highFunction == null) {
                        throw new ToolExecutionException("No high function available");
                    }
                    
                    // Find the symbol by name
                    HighSymbol symbol = findSymbolByName(highFunction, variableName);
                    if (symbol == null) {
                        throw new ToolExecutionException("Variable '" + variableName + "' not found in function");
                    }
                    
                    // Resolve data type
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = resolveDataType(dtm, newType);
                    if (dataType == null) {
                        throw new ToolExecutionException("Could not resolve data type: " + newType);
                    }
                    
                    // Apply the type change on EDT
                    AtomicBoolean success = new AtomicBoolean(false);
                    AtomicBoolean exceptionOccurred = new AtomicBoolean(false);
                    RuntimeException[] exceptionHolder = new RuntimeException[1];
                    
                    SwingUtilities.invokeAndWait(() -> {
                        try {
                            int tx = program.startTransaction("Set local variable type");
                            try {
                                HighFunctionDBUtil.updateDBVariable(
                                    symbol,
                                    symbol.getName(),
                                    dataType,
                                    SourceType.USER_DEFINED
                                );
                                success.set(true);
                            } finally {
                                program.endTransaction(tx, success.get());
                            }
                        } catch (Exception e) {
                            exceptionOccurred.set(true);
                            exceptionHolder[0] = new RuntimeException("Failed to set variable type: " + e.getMessage(), e);
                        }
                    });
                    
                    if (exceptionOccurred.get()) {
                        throw exceptionHolder[0];
                    }
                    
                    if (!success.get()) {
                        throw new ToolExecutionException("Failed to set variable type");
                    }
                    
                    return String.format("Successfully set type of variable '%s' to '%s' in function at %s",
                        variableName, newType, functionAddress);
                } finally {
                    decompiler.closeProgram();
                }
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to set local variable type: " + e.getMessage(), e);
            }
        });
    }
    
    /**
     * Find a high symbol by name in the given high function.
     */
    private HighSymbol findSymbolByName(HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }
    
    /**
     * Resolve a data type by name.
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType dt = dtm.getDataType("/" + typeName);
        if (dt != null) {
            return dt;
        }
        
        // Try common types
        String lowerType = typeName.toLowerCase();
        switch (lowerType) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "void":
                return dtm.getDataType("/void");
        }
        
        // Try pointer types (e.g., "char *", "int*")
        if (typeName.contains("*")) {
            String baseTypeName = typeName.replace("*", "").trim();
            DataType baseType = resolveDataType(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }
        }
        
        // Search all data types
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType candidate = allTypes.next();
            if (candidate.getName().equalsIgnoreCase(typeName)) {
                return candidate;
            }
        }
        
        return null;
    }
}
