package com.zenyard.decompai.ghidra.illum;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.zenyard.decompai.ghidra.api.generated.model.FunctionOverview;
import com.zenyard.decompai.ghidra.api.generated.model.Inference;
import com.zenyard.decompai.ghidra.api.generated.model.Name;
import com.zenyard.decompai.ghidra.api.generated.model.ParametersMapping;
import com.zenyard.decompai.ghidra.api.generated.model.SwiftFunction;
import com.zenyard.decompai.ghidra.api.generated.model.VariablesMapping;
import com.zenyard.decompai.ghidra.storage.InferenceStorage;
import com.zenyard.decompai.ghidra.util.DecompaiConstants;
import com.zenyard.decompai.ghidra.util.TransactionUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Handles applying all inference types to a Ghidra program.
 * 
 * NOTE: mirrors decompai_ida/inferences.py apply_inferences_sync() logic
 * 
 * All program modifications use Ghidra's transaction system for atomic updates.
 */
public class InferenceApplier {
    
    private final FunctionOverviewAnnotator overviewAnnotator;
    private final InferenceStorage inferenceStorage;
    private final VariableRenamer variableRenamer;
    private final ParameterRenamer parameterRenamer;
    private final PluginTool tool;
    
    public InferenceApplier(FunctionOverviewAnnotator overviewAnnotator, InferenceStorage inferenceStorage) {
        this(overviewAnnotator, inferenceStorage, null);
    }
    
    public InferenceApplier(FunctionOverviewAnnotator overviewAnnotator, InferenceStorage inferenceStorage, PluginTool tool) {
        this.overviewAnnotator = overviewAnnotator;
        this.inferenceStorage = inferenceStorage;
        this.variableRenamer = new VariableRenamer(inferenceStorage);
        this.parameterRenamer = new ParameterRenamer();
        this.tool = tool;
    }
    
    /**
     * Apply a list of inferences to the program.
     * Groups inferences by address and applies them in order.
     * 
     * @param program The program to modify
     * @param inferences List of inferences to apply
     */
    public void applyInferences(Program program, List<Inference> inferences) {
        if (inferences == null || inferences.isEmpty()) {
            return;
        }
        
        // Group inferences by address
        Map<Address, List<Inference>> byAddress = new HashMap<>();
        for (Inference inference : inferences) {
            // Get address from the actual instance
            String addressStr = getAddressFromInference(inference);
            Address addr = parseAddress(addressStr, program);
            if (addr != null) {
                byAddress.computeIfAbsent(addr, k -> new ArrayList<>()).add(inference);
            }
        }
        
        // Apply inferences for each address
        for (Map.Entry<Address, List<Inference>> entry : byAddress.entrySet()) {
            applyInferencesForAddress(program, entry.getKey(), entry.getValue());
        }
    }
    
    /**
     * Apply inferences for a specific address.
     */
    private void applyInferencesForAddress(Program program, Address address, List<Inference> inferences) {
        TransactionUtils.runInTransaction(program, "DecompAI: Apply inferences", () -> {
            for (Inference inference : inferences) {
                try {
                    applyInference(program, address, inference);
                    
                    // Store inference data
                    Map<String, Object> inferenceData = serializeInferenceData(inference);
                    String inferenceType = getInferenceType(inference);
                    String addressStr = getAddressFromInference(inference);
                    if (addressStr == null) {
                        addressStr = address.toString();
                    }
                    inferenceStorage.storeInference(
                        addressStr + "." + inferenceType,
                        new InferenceStorage.InferenceData(
                            addressStr,
                            inferenceType,
                            inferenceData
                        )
                    );
                } catch (Exception e) {
                    Msg.warn(this, "Error applying inference at " + address + ": " + e.getMessage(), e);
                    // Continue with other inferences
                }
            }
        });
    }
    
    /**
     * Get inference type from generated Inference object.
     */
    private String getInferenceType(Inference inference) {
        // The generated Inference uses getActualInstance() to get the concrete type
        Object actual = inference.getActualInstance();
        if (actual instanceof FunctionOverview) {
            return "function_overview";
        } else if (actual instanceof Name) {
            return "name";
        } else if (actual instanceof VariablesMapping) {
            return "variables";
        } else if (actual instanceof ParametersMapping) {
            return "params";
        } else if (actual instanceof SwiftFunction) {
            return "swift_function";
        } else if (actual instanceof java.util.Map) {
            Object type = ((java.util.Map<?, ?>) actual).get("type");
            return type != null ? String.valueOf(type) : "unknown";
        }
        return "unknown";
    }
    
    /**
     * Get address string from inference.
     */
    private String getAddressFromInference(Inference inference) {
        Object actual = inference.getActualInstance();
        if (actual instanceof FunctionOverview) {
            return ((FunctionOverview) actual).getAddress();
        } else if (actual instanceof Name) {
            return ((Name) actual).getAddress();
        } else if (actual instanceof VariablesMapping) {
            return ((VariablesMapping) actual).getAddress();
        } else if (actual instanceof ParametersMapping) {
            return ((ParametersMapping) actual).getAddress();
        } else if (actual instanceof SwiftFunction) {
            return ((SwiftFunction) actual).getAddress();
        } else if (actual instanceof java.util.Map) {
            Object address = ((java.util.Map<?, ?>) actual).get("address");
            if (address instanceof String) {
                return (String) address;
            }
            if (address instanceof java.util.Map) {
                Object root = ((java.util.Map<?, ?>) address).get("root");
                if (root != null) {
                    return String.valueOf(root);
                }
            }
        }
        return null;
    }
    
    /**
     * Apply a single inference.
     */
    private void applyInference(Program program, Address address, Inference inference) {
        Object actual = inference.getActualInstance();
        
        if (actual instanceof FunctionOverview) {
            applyFunctionOverview(program, address, (FunctionOverview) actual);
        } else if (actual instanceof Name) {
            Msg.debug(this, "Applying name inference at " + address);
            applyName(program, address, (Name) actual);
        } else if (actual instanceof VariablesMapping) {
            applyVariablesMapping(program, address, (VariablesMapping) actual);
        } else if (actual instanceof ParametersMapping) {
            applyParametersMapping(program, address, (ParametersMapping) actual);
        } else if (actual instanceof SwiftFunction) {
            // SwiftFunction is read-only, nothing to apply
            // Just store it for later retrieval
        } else if (actual instanceof java.util.Map) {
            applyMapInference(program, address, (java.util.Map<?, ?>) actual);
        } else {
            Msg.warn(this, "Unknown inference type: " + actual.getClass().getSimpleName());
        }
    }

    private void applyMapInference(Program program, Address address, java.util.Map<?, ?> actual) {
        Object type = actual.get("type");
        if (type == null) {
            Msg.warn(this, "Unknown inference map with no type at " + address);
            return;
        }
        String typeValue = String.valueOf(type);
        if ("name".equals(typeValue)) {
            Object nameValue = actual.get("name");
            if (nameValue != null) {
                Msg.debug(this, "Applying map-based name inference at " + address);
                applyNameString(program, address, String.valueOf(nameValue));
            }
            return;
        }
        Msg.warn(this, "Unhandled inference map type '" + typeValue + "' at " + address);
    }
    
    /**
     * Apply function overview inference.
     */
    private void applyFunctionOverview(Program program, Address address, FunctionOverview overview) {
        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionAt(address);
        
        if (function == null) {
            Msg.warn(this, "No function at address " + address);
            return;
        }
        
        // Check if user has defined a comment
        if (hasUserDefinedComment(program, function)) {
            return; // Don't override user comments
        }
        
        // Apply overview as plate comment
        overviewAnnotator.addOverview(program, function, overview.getFullDescription());
    }
    
    /**
     * Apply name inference.
     */
    private void applyName(Program program, Address address, Name name) {
        // Check if user has defined a name
        if (hasUserDefinedName(program, address)) {
            Msg.debug(this, "Skipping name inference at " + address + ": user-defined name");
            return; // Don't override user names
        }
        
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol symbol = symbolTable.getPrimarySymbol(address);
        
        if (symbol == null) {
            Msg.warn(this, "No symbol at address " + address);
            return;
        }
        
        // Check if it's a thunk
        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionAt(address);
        if (function != null && function.isThunk()) {
            // Don't rename thunks - let Ghidra manage them
            Msg.debug(this, "Skipping name inference at " + address + ": thunk function");
            return;
        }
        
        // Apply name
        String nameToApply = name.getName();
        applyNameString(program, address, nameToApply);
    }

    private void applyNameString(Program program, Address address, String nameToApply) {
        if (hasUserDefinedName(program, address)) {
            Msg.debug(this, "Skipping name inference at " + address + ": user-defined name");
            return;
        }
        if (nameToApply == null || nameToApply.isEmpty()) {
            Msg.debug(this, "Skipping name inference at " + address + ": empty name");
            return;
        }
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol symbol = symbolTable.getPrimarySymbol(address);
        if (symbol == null) {
            Msg.warn(this, "No symbol at address " + address);
            return;
        }
        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionAt(address);
        if (function != null && function.isThunk()) {
            Msg.debug(this, "Skipping name inference at " + address + ": thunk function");
            return;
        }
        // Add leading underscore if name is a reserved prefix
        if (!isValidName(nameToApply)) {
            nameToApply = "_" + nameToApply;
        }

        String currentName = symbol.getName();
        if (currentName != null && currentName.equals(nameToApply)) {
            Msg.debug(this, "Skipping name inference at " + address + ": no change (" + currentName + ")");
            return;
        }
        
        try {
            symbol.setName(nameToApply, SourceType.ANALYSIS);
            Msg.info(this, "Renamed function at " + address + " to " + nameToApply);
            if (function != null) {
                FunctionListHighlighter.markFunctionRenamed(function);
                FunctionListHighlighter.installRenderer(tool);
                SymbolTreeHighlighter.installRenderer(tool);
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to rename symbol at " + address + ": " + e.getMessage(), e);
        }
    }
    
    /**
     * Apply variables mapping inference.
     */
    private void applyVariablesMapping(Program program, Address address, VariablesMapping mapping) {
        if (variableRenamer != null) {
            variableRenamer.applyVariablesMapping(program, address, mapping);
            return;
        }
        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionAt(address);
        
        if (function == null) {
            Msg.warn(this, "No function at address " + address);
            return;
        }
        
        // Decompile function
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);
        
        try {
            DecompileOptions options = new DecompileOptions();
            decompiler.setOptions(options);
            
            DecompileResults results = decompiler.decompileFunction(
                function,
                DecompaiConstants.DECOMPILER_TIMEOUT_SECONDS,
                TaskMonitor.DUMMY
            );
            
            if (!results.decompileCompleted()) {
                throw new RuntimeException("Failed to decompile function: " 
                    + (results.getErrorMessage() != null ? results.getErrorMessage() : "Unknown error"));
            }
            
            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.warn(this, "No HighFunction available for " + address);
                return;
            }
            
            // Get variable names from decompiled function
            LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
            Iterator<HighSymbol> localSymbolsIter = localSymbolMap.getSymbols();
            List<HighSymbol> localSymbols = new ArrayList<>();
            localSymbolsIter.forEachRemaining(localSymbols::add);
            
            // Build map of variable names to HighSymbol objects (for renaming)
            Map<String, HighSymbol> variableNameToSymbol = new HashMap<>();
            for (HighSymbol symbol : localSymbols) {
                HighVariable var = symbol.getHighVariable();
                if (var != null) {
                    String varName = var.getName();
                    if (varName != null && !varName.isEmpty()) {
                        variableNameToSymbol.put(varName, symbol);
                    }
                }
            }
            
            // Get last inferred variable names from storage (if any)
            VariablesMapping lastMapping = inferenceStorage.getLastVariablesMapping(address);
            java.util.Set<String> lastInferredNames = new java.util.HashSet<>();
            if (lastMapping != null) {
                lastInferredNames.addAll(lastMapping.getVariablesMapping().values());
            }
            
            // Filter renames - only rename dummy variables or previously inferred variables
            Map<String, String> renames = new HashMap<>();
            Map<String, String> variablesMapping = mapping.getVariablesMapping();
            
            for (Map.Entry<String, String> entry : variablesMapping.entrySet()) {
                String originalName = entry.getKey();
                String newName = entry.getValue();
                
                HighSymbol symbol = variableNameToSymbol.get(originalName);
                if (symbol == null) {
                    continue; // Variable not found
                }
                
                HighVariable var = symbol.getHighVariable();
                if (var == null) {
                    continue;
                }
                
                // Check if variable is dummy (auto-generated) or was previously inferred
                boolean isDummy = var.getName().startsWith("uVar") 
                                 || var.getName().startsWith("local_") 
                                 || var.getName().matches("^[a-z]\\d+$"); // Pattern like "v3", "v4"
                
                if (isDummy || lastInferredNames.contains(originalName)) {
                    renames.put(originalName, newName);
                }
            }
            
            boolean localsCommitted = false;

            // Apply renames using Variable.setName() from public Ghidra API
            // Reference: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Variable.html
            for (Map.Entry<String, String> rename : renames.entrySet()) {
                String fromName = rename.getKey();
                String toName = rename.getValue();
                
                HighSymbol symbol = variableNameToSymbol.get(fromName);
                if (symbol != null) {
                    try {
                        // Validate name first
                        String nameToApply = toName;
                        if (!isValidName(nameToApply)) {
                            // Add underscore prefix for invalid names
                            nameToApply = "_" + nameToApply;
                        }
                        
                        HighVariable highVar = symbol.getHighVariable();
                        if (highVar != null) {
                            ghidra.program.model.pcode.Varnode storage = highVar.getRepresentative();
                            if (storage == null) {
                                Msg.debug(this, "Skipping rename for " + fromName + " at " + address 
                                    + ": no representative storage");
                                continue;
                            }

                            Address storageAddress = storage.getAddress();
                            if (storageAddress.isUniqueAddress()) {
                                Msg.debug(this, "Skipping rename for " + fromName + " at " + address 
                                    + ": temporary unique storage");
                                continue;
                            }

                            if (!storageAddress.isStackAddress() && !storageAddress.isRegisterAddress()) {
                                Msg.debug(this, "Skipping rename for " + fromName + " at " + address 
                                    + ": non-local storage " + storageAddress);
                                continue;
                            }

                            LocalVariable localVar = findLocalVariableByStorage(function, storage);
                            if (localVar == null && !localsCommitted) {
                                try {
                                    HighFunctionDBUtil.commitLocalNamesToDatabase(highFunction, SourceType.ANALYSIS);
                                    localsCommitted = true;
                                    localVar = findLocalVariableByStorage(function, storage);
                                } catch (Exception e) {
                                    Msg.warn(this, "Failed to commit locals at " + address + ": " + e.getMessage(), e);
                                }
                            }

                            if (localVar != null) {
                                try {
                                    localVar.setName(nameToApply, SourceType.ANALYSIS);
                                    Msg.debug(this, "Renamed variable " + fromName + " -> " + nameToApply + " at " + address);
                                } catch (DuplicateNameException e) {
                                    Msg.warn(this, "Cannot rename variable " + fromName + " to " + nameToApply 
                                        + ": duplicate name at " + address);
                                } catch (InvalidInputException e) {
                                    Msg.warn(this, "Cannot rename variable " + fromName + " to " + nameToApply 
                                        + ": invalid name at " + address + ": " + e.getMessage());
                                }
                            } else {
                                Msg.debug(this, "No LocalVariable for storage of " + fromName + " at " + address);
                            }
                        }
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to rename variable " + fromName + " to " + toName 
                            + " at " + address + ": " + e.getMessage(), e);
                    }
                }
            }
            
            // Store last variables mapping for future reference
            if (!renames.isEmpty()) {
                inferenceStorage.storeLastVariablesMapping(address, mapping);
            }
            
        } catch (Exception e) {
            Msg.warn(this, "Failed to apply variables mapping at " + address + ": " + e.getMessage(), e);
        } finally {
            decompiler.closeProgram();
        }
    }
    
    /**
     * Apply parameters mapping inference.
     */
    private void applyParametersMapping(Program program, Address address, ParametersMapping mapping) {
        if (parameterRenamer != null) {
            parameterRenamer.applyParametersMapping(program, address, mapping);
            return;
        }
        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionAt(address);
        
        if (function == null) {
            Msg.warn(this, "No function at address " + address);
            return;
        }
        
        // Get parameter names
        Parameter[] parameters = function.getParameters();
        Map<String, String> parametersMapping = mapping.getParametersMapping();
        if (parametersMapping == null || parametersMapping.isEmpty()) {
            Msg.debug(this, "No parameters mapping data for " + address);
            return;
        }

        // If function has no parameters in listing, commit decompiler params first
        if (parameters.length == 0) {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(program);
            try {
                DecompileOptions options = new DecompileOptions();
                decompiler.setOptions(options);

                DecompileResults results = decompiler.decompileFunction(
                    function,
                    DecompaiConstants.DECOMPILER_TIMEOUT_SECONDS,
                    TaskMonitor.DUMMY
                );

                if (!results.decompileCompleted()) {
                    Msg.warn(this, "Failed to decompile function for params at " + address + ": " 
                        + (results.getErrorMessage() != null ? results.getErrorMessage() : "Unknown error"));
                } else {
                    HighFunction highFunction = results.getHighFunction();
                    if (highFunction != null) {
                        HighFunctionDBUtil.commitParamsToDatabase(
                            highFunction,
                            true,
                            HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,
                            SourceType.ANALYSIS
                        );
                        parameters = function.getParameters();
                    }
                }
            } catch (Exception e) {
                Msg.warn(this, "Failed to commit parameters for " + address + ": " + e.getMessage(), e);
            } finally {
                decompiler.closeProgram();
            }
        }

        List<String> parameterNames = new ArrayList<>();
        for (Parameter parameter : parameters) {
            parameterNames.add(parameter.getName());
        }
        Msg.debug(this, "Apply params mapping at " + address + " keys=" + parametersMapping.keySet() 
            + " params=" + parameterNames);
        
        // Get last inferred parameter names from storage (if any)
        ParametersMapping lastMapping = inferenceStorage.getLastParametersMapping(address);
        java.util.Set<String> lastInferredNames = new java.util.HashSet<>();
        if (lastMapping != null) {
            lastInferredNames.addAll(lastMapping.getParametersMapping().values());
        }
        
        // Build map of parameter index to new name
        Map<Integer, String> renames = new HashMap<>();
        
        for (int i = 0; i < parameters.length; i++) {
            Parameter param = parameters[i];
            String originalName = param.getName();
            String newName = resolveParameterMappingName(parametersMapping, originalName, i);
            
            if (newName == null || newName.equals(originalName)) {
                continue;
            }
            
            // Check if parameter is dummy (auto-generated) or was previously inferred
            boolean isDummy = originalName == null || originalName.isEmpty() 
                             || originalName.startsWith("param_") 
                             || originalName.startsWith("arg") 
                             || originalName.matches("^[a-z]\\d+$"); // Pattern like "v3", "v4"
            
            if (isDummy || lastInferredNames.contains(originalName)) {
                renames.put(i, newName);
            }
        }
        
        // Apply renames by setting parameter names directly
        if (!renames.isEmpty()) {
            try {
                for (Map.Entry<Integer, String> rename : renames.entrySet()) {
                    int paramIndex = rename.getKey();
                    String newName = rename.getValue();
                    
                    if (paramIndex >= 0 && paramIndex < parameters.length) {
                        Parameter param = parameters[paramIndex];
                        // Rename parameter using setName
                        String nameToApply = newName;
                        if (!isValidName(nameToApply)) {
                            nameToApply = "_" + nameToApply;
                        }
                        try {
                            param.setName(nameToApply, SourceType.ANALYSIS);
                        } catch (DuplicateNameException e) {
                            Msg.warn(this, "Cannot rename parameter " + param.getName() + " to " + nameToApply 
                                + ": duplicate name at " + address);
                        } catch (InvalidInputException e) {
                            Msg.warn(this, "Cannot rename parameter " + param.getName() + " to " + nameToApply 
                                + ": invalid name at " + address + ": " + e.getMessage());
                        }
                    }
                }
                
                // Store last parameters mapping for future reference
                inferenceStorage.storeLastParametersMapping(address, mapping);
                
            } catch (Exception e) {
                Msg.warn(this, "Failed to apply parameters mapping at " + address + ": " + e.getMessage(), e);
            }
        } else {
            Msg.debug(this, "No parameter renames applied at " + address);
        }
    }

    /**
     * Resolve parameter rename from mapping using name or index-based keys.
     */
    private String resolveParameterMappingName(Map<String, String> parametersMapping, String originalName, int index) {
        if (originalName != null && !originalName.isEmpty()) {
            String byName = parametersMapping.get(originalName);
            if (byName != null) {
                return byName;
            }
        }

        String byParamKey = parametersMapping.get("param_" + (index + 1));
        if (byParamKey != null) {
            return byParamKey;
        }

        String byArgKey = parametersMapping.get("arg" + (index + 1));
        if (byArgKey != null) {
            return byArgKey;
        }

        String byZeroBasedIndex = parametersMapping.get(String.valueOf(index));
        if (byZeroBasedIndex != null) {
            return byZeroBasedIndex;
        }

        return parametersMapping.get(String.valueOf(index + 1));
    }
    
    /**
     * Check if address has a user-defined name.
     */
    private boolean hasUserDefinedName(Program program, Address address) {
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol symbol = symbolTable.getPrimarySymbol(address);
        
        if (symbol == null) {
            return false;
        }
        
        // Check if name source is user-defined (not default/analysis)
        SourceType source = symbol.getSource();
        return source == SourceType.USER_DEFINED;
    }
    
    /**
     * Check if function has a user-defined comment.
     */
    private boolean hasUserDefinedComment(Program program, Function function) {
        String comment = function.getComment();
        if (comment == null || comment.trim().isEmpty()) {
            return false;
        }
        
        // Check if comment was inferred (stored in inference storage)
        // TODO: Check inference storage to see if this comment was inferred
        // For now, assume any comment is user-defined
        return true;
    }
    
    /**
     * Find a LocalVariable by storage location.
     * 
     * @param function The function containing the variable
     * @param storage The storage varnode from HighVariable
     * @return The matching LocalVariable or null if not found
     */
    private LocalVariable findLocalVariableByStorage(Function function, ghidra.program.model.pcode.Varnode storage) {
        if (function == null || storage == null) {
            return null;
        }
        
        // Get all local variables from the function
        Variable[] variables = function.getLocalVariables();
        Map<LocalVariable, String> relaxedCandidates = new HashMap<>();
        for (Variable var : variables) {
            if (var instanceof LocalVariable) {
                LocalVariable localVar = (LocalVariable) var;
                ghidra.program.model.pcode.Varnode[] varnodes = localVar.getVariableStorage().getVarnodes();
                if (varnodes == null || varnodes.length == 0) {
                    continue;
                }

                for (ghidra.program.model.pcode.Varnode varnode : varnodes) {
                    if (varnode == null) {
                        continue;
                    }

                    boolean addressMatch = storage.getAddress().equals(varnode.getAddress());
                    boolean sizeMatch = storage.getSize() == varnode.getSize();

                    if (addressMatch && sizeMatch) {
                        Msg.debug(this, "Strict storage match for " + localVar.getName() 
                            + " at " + storage.getAddress() + " size " + storage.getSize());
                        return localVar;
                    }

                    if (addressMatch && !sizeMatch && isLikelyDummyVariableName(localVar.getName())) {
                        String reason = "address match size mismatch";
                        relaxedCandidates.putIfAbsent(localVar, reason);
                    }
                }
            }
        }

        if (relaxedCandidates.size() == 1) {
            Map.Entry<LocalVariable, String> candidate = relaxedCandidates.entrySet().iterator().next();
            LocalVariable localVar = candidate.getKey();
            Msg.debug(this, "Relaxed storage match for " + localVar.getName() 
                + " (" + candidate.getValue() + ") at " + storage.getAddress() 
                + " size " + storage.getSize());
            return localVar;
        }

        if (relaxedCandidates.size() > 1) {
            List<String> names = new ArrayList<>();
            for (LocalVariable candidate : relaxedCandidates.keySet()) {
                names.add(candidate.getName());
            }
            Msg.debug(this, "Ambiguous relaxed storage match at " + storage.getAddress() 
                + " size " + storage.getSize() + ": candidates " + names);
        }

        return null;
    }

    private boolean isLikelyDummyVariableName(String name) {
        if (name == null || name.isEmpty()) {
            return true;
        }
        return name.startsWith("uVar") 
               || name.startsWith("local_") 
               || name.matches("^[a-z]\\d+$");
    }
    
    /**
     * Check if a name is valid (not a reserved prefix).
     */
    private boolean isValidName(String name) {
        // Check for common reserved prefixes
        return !name.startsWith("byte_") 
               && !name.startsWith("word_") 
               && !name.startsWith("dword_") 
               && !name.startsWith("qword_");
    }
    
    /**
     * Parse address from API address string (16-character hex) to Ghidra Address.
     */
    private Address parseAddress(String apiAddress, Program program) {
        if (apiAddress == null || program == null) {
            return null;
        }
        
        try {
            // API addresses are 16-character lowercase hexadecimal strings
            long offset = Long.parseLong(apiAddress, 16);
            AddressFactory addressFactory = program.getAddressFactory();
            return addressFactory.getDefaultAddressSpace().getAddress(offset);
        } catch (Exception e) {
            Msg.warn(this, "Failed to parse address: " + apiAddress + ": " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Serialize inference data to a map for storage.
     */
    private Map<String, Object> serializeInferenceData(Inference inference) {
        Map<String, Object> data = new HashMap<>();
        Gson gson = new GsonBuilder().create();
        Object actual = inference.getActualInstance();
        
        // Serialize based on inference type
        if (actual instanceof FunctionOverview) {
            FunctionOverview overview = (FunctionOverview) actual;
            data.put("overview", overview.getOverview());
        } else if (actual instanceof Name) {
            Name name = (Name) actual;
            data.put("name", name.getName());
        } else if (actual instanceof VariablesMapping) {
            VariablesMapping mapping = (VariablesMapping) actual;
            data.put("variables_mapping", mapping.getVariablesMapping());
        } else if (actual instanceof ParametersMapping) {
            ParametersMapping mapping = (ParametersMapping) actual;
            data.put("parameters_mapping", mapping.getParametersMapping());
        } else if (actual instanceof SwiftFunction) {
            SwiftFunction swift = (SwiftFunction) actual;
            data.put("swift_function", gson.toJsonTree(swift).getAsJsonObject());
        } else {
            // Generic serialization for unknown types
            data.put("raw_data", gson.toJsonTree(inference).getAsJsonObject());
        }
        
        return data;
    }
}

