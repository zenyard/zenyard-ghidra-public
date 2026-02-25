package com.zenyard.ghidra.illum;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.function.UnaryOperator;
import java.util.function.BooleanSupplier;
import com.zenyard.ghidra.api.generated.model.FieldDefinition;
import com.zenyard.ghidra.api.generated.model.FunctionOverview;
import com.zenyard.ghidra.api.generated.model.Inference;
import com.zenyard.ghidra.api.generated.model.Name;
import com.zenyard.ghidra.api.generated.model.NotSwift;
import com.zenyard.ghidra.api.generated.model.ParameterType;
import com.zenyard.ghidra.api.generated.model.ParametersMapping;
import com.zenyard.ghidra.api.generated.model.ReturnType;
import com.zenyard.ghidra.api.generated.model.StructDefinition;
import com.zenyard.ghidra.api.generated.model.SwiftFunction;
import com.zenyard.ghidra.api.generated.model.VariablesMapping;
import com.zenyard.ghidra.storage.InferenceStorage;
import com.zenyard.ghidra.util.ZenyardConstants;
import com.zenyard.ghidra.util.TransactionUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.CommentType;
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
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Handles applying all inference types to a Ghidra program.
 * 
 * NOTE: mirrors zenyard_ida/inferences.py apply_inferences_sync() logic
 * 
 * All program modifications use Ghidra's transaction system for atomic updates.
 */
public class InferenceApplier {
    
    private final FunctionOverviewAnnotator overviewAnnotator;
    private final InferenceStorage inferenceStorage;
    private final VariableRenamer variableRenamer;
    private final StructInferenceApplier structInferenceApplier;
    private final FunctionTypeInferenceApplier functionTypeInferenceApplier;
    private final MergedStructCleaner mergedStructCleaner;
    private final PluginTool tool;
    private static final int MAX_DEFERRED_RETRY_ATTEMPTS = 3;
    private static final Pattern FUN_TOKEN_PATTERN = Pattern.compile("\\bFUN_([0-9a-fA-F]+)\\b");
    // Batch-scoped: addresses where return_type or parameter_type was successfully applied.
    // Cleared at the start of each applyInferences call.
    private final Set<Address> typeChangedAddresses = new HashSet<>();
    // Per-applier (session) guard: the return-type catch-up scan is expensive and
    // should not run once per mini-batch.
    private boolean hasRunReturnTypeLocalPropagationCatchUp = false;

    public InferenceApplier(FunctionOverviewAnnotator overviewAnnotator, InferenceStorage inferenceStorage) {
        this(overviewAnnotator, inferenceStorage, null);
    }

    public InferenceApplier(FunctionOverviewAnnotator overviewAnnotator, InferenceStorage inferenceStorage, PluginTool tool) {
        this.overviewAnnotator = overviewAnnotator;
        this.inferenceStorage = inferenceStorage;
        this.variableRenamer = new VariableRenamer(inferenceStorage);
        this.structInferenceApplier = new StructInferenceApplier(inferenceStorage);
        this.functionTypeInferenceApplier = new FunctionTypeInferenceApplier(inferenceStorage, structInferenceApplier);
        this.mergedStructCleaner = new MergedStructCleaner(inferenceStorage, structInferenceApplier);
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
        applyInferences(program, inferences, TaskMonitor.DUMMY, () -> false);
    }

    /**
     * Apply inferences with cancellation support.
     */
    public void applyInferences(Program program, List<Inference> inferences, TaskMonitor monitor) {
        applyInferences(program, inferences, monitor, () -> false);
    }

    /**
     * Apply inferences with cancellation + external stop flag support.
     * <p>
     * The stop flag is primarily used to abort work during PROGRAM_DEACTIVATED (close) events,
     * where the task thread may still be mid-batch.
     */
    public void applyInferences(
        Program program,
        List<Inference> inferences,
        TaskMonitor monitor,
        BooleanSupplier shouldStop
    ) {
        if (inferences == null || inferences.isEmpty()) {
            return;
        }
        if (program == null || program.isClosed()) {
            return;
        }

        typeChangedAddresses.clear();

        applyStructDefinitions(program, inferences);
        
        // Group inferences by address
        Map<Address, List<Inference>> byAddress = new HashMap<>();
        List<Inference> globalInferences = new ArrayList<>();
        for (Inference inference : inferences) {
            if ("struct_definition".equals(getInferenceType(inference))) {
                continue;
            }
            // Get address from the actual instance
            String addressStr = getAddressFromInference(inference);
            if (addressStr == null) {
                globalInferences.add(inference);
                continue;
            }
            Address addr = parseAddress(addressStr, program);
            if (addr != null) {
                byAddress.computeIfAbsent(addr, k -> new ArrayList<>()).add(inference);
            }
        }

        if (!globalInferences.isEmpty()) {
            globalInferences.sort(Comparator.comparingInt(this::getInferencePriority));
            applyGlobalInferences(program, globalInferences, monitor, shouldStop);
        }
        
        // Apply inferences for each address (populates typeChangedAddresses)
        for (Map.Entry<Address, List<Inference>> entry : byAddress.entrySet()) {
            if (shouldStop != null && shouldStop.getAsBoolean()) {
                return;
            }
            if (monitor != null && monitor.isCancelled()) {
                return;
            }
            List<Inference> sorted = new ArrayList<>(entry.getValue());
            sorted.sort(Comparator.comparingInt(this::getInferencePriority));
            applyInferencesForAddress(program, entry.getKey(), sorted, monitor, shouldStop);
        }

        if (shouldStop != null && shouldStop.getAsBoolean()) {
            return;
        }
        if (monitor != null && monitor.isCancelled()) {
            return;
        }
        retryDeferredTypeInferences(program, monitor);

        // Catch-up: propagate return types to returned local variables for functions
        // whose return_type was applied in a previous session but local propagation
        // was not completed (e.g. the method didn't exist yet or failed).
        //
        // This scan can be expensive. Run it once per applier instance (session) and
        // avoid holding a long-lived transaction open while decompiling.
        if (!hasRunReturnTypeLocalPropagationCatchUp) {
            hasRunReturnTypeLocalPropagationCatchUp = true;
            long started = System.currentTimeMillis();
            Set<Address> propagated = functionTypeInferenceApplier.ensureReturnTypeLocalPropagation(
                program,
                monitor,
                shouldStop != null ? shouldStop : () -> false
            );
            typeChangedAddresses.addAll(propagated);
            long elapsedMs = System.currentTimeMillis() - started;
            if (!propagated.isEmpty()) {
                Msg.info(this, "Return type local propagation catch-up finished: propagated "
                    + propagated.size() + " functions in " + elapsedMs + "ms");
            }
        }

        if (shouldStop != null && shouldStop.getAsBoolean()) {
            return;
        }
        if (monitor != null && monitor.isCancelled()) {
            return;
        }
        if (program == null || program.isClosed()) {
            return;
        }

        // Post-batch verification: re-decompile functions that had variable renames
        // applied IN THIS BATCH and re-apply any renames that didn't survive.
        TransactionUtils.runInTransaction(program, "Zenyard: Post-batch rename verification", () -> {
            variableRenamer.runPendingVerifications(program);
        });

        // Type-change rename refresh: for functions whose return_type, parameter_type,
        // or local type was changed in this batch, refresh their own stored renames
        // (the function's re-decompilation can revert register-based local renames)
        // AND refresh their callers' stored renames (callee signature changes alter
        // the caller's decompilation layout).
        if (!typeChangedAddresses.isEmpty()) {
            if (shouldStop != null && shouldStop.getAsBoolean()) {
                return;
            }
            if (monitor != null && monitor.isCancelled()) {
                return;
            }
            if (program == null || program.isClosed()) {
                return;
            }
            TransactionUtils.runInTransaction(program, "Zenyard: Type-change rename refresh", () -> {
                variableRenamer.refreshCallerRenames(program, typeChangedAddresses, monitor, shouldStop);
            });
        }

        if (shouldStop != null && shouldStop.getAsBoolean()) {
            return;
        }
        if (monitor != null && monitor.isCancelled()) {
            return;
        }
        if (program != null && !program.isClosed()) {
            try {
                mergedStructCleaner.cleanupMergedOrphanStructs(program, inferences, monitor);
            } catch (Exception e) {
                Msg.warn(this, "Merged-struct cleanup failed: " + e.getMessage(), e);
            }
        }

        refreshFunctionOverviewInferences(program, inferences);
    }

    private void applyGlobalInferences(
        Program program,
        List<Inference> inferences,
        TaskMonitor monitor,
        BooleanSupplier shouldStop
    ) {
        TransactionUtils.runInTransaction(program, "Zenyard: Apply global inferences", () -> {
            for (Inference inference : inferences) {
                if (shouldStop != null && shouldStop.getAsBoolean()) {
                    return;
                }
                if (monitor != null && monitor.isCancelled()) {
                    return;
                }
                try {
                    applyInference(program, null, inference, monitor);
                    Map<String, Object> inferenceData = serializeInferenceData(inference);
                    String inferenceType = getInferenceType(inference);
                    String inferenceId = getGlobalInferenceId(inference, inferenceType);
                    inferenceStorage.storeInference(
                        inferenceId,
                        new InferenceStorage.InferenceData(
                            inferenceId,
                            inferenceType,
                            inferenceData
                        )
                    );
                } catch (Exception e) {
                    Msg.warn(this, "Error applying global inference " + getInferenceType(inference) + ": " + e.getMessage(), e);
                }
            }
        });
    }
    
    /**
     * Apply inferences for a specific address.
     */
    private void applyInferencesForAddress(
        Program program,
        Address address,
        List<Inference> inferences,
        TaskMonitor monitor,
        BooleanSupplier shouldStop
    ) {
        List<Inference> localsFirst = new ArrayList<>();
        List<Inference> prototypeLast = new ArrayList<>();
        for (Inference inference : inferences) {
            if (isFunctionPrototypeInference(inference)) {
                prototypeLast.add(inference);
            } else {
                localsFirst.add(inference);
            }
        }
        // Deterministic order inside each phase.
        localsFirst.sort(Comparator.comparingInt(this::getInferencePriority));
        prototypeLast.sort(Comparator.comparingInt(this::getInferencePriority));

        TransactionUtils.runInTransaction(program, "Zenyard: Apply inferences", () -> {
            for (Inference inference : localsFirst) {
                if (shouldStop != null && shouldStop.getAsBoolean()) {
                    return;
                }
                if (monitor != null && monitor.isCancelled()) {
                    return;
                }
                try {
                    applyAndStoreInference(program, address, inference, monitor);
                } catch (Exception e) {
                    Msg.warn(this, "Error applying inference at " + address + ": " + e.getMessage(), e);
                    // Continue with other inferences
                }
            }
            // Function prototype changes can trigger re-decompilation and rewrite local names,
            // so apply them only after all local variable/parameter naming inferences.
            for (Inference inference : prototypeLast) {
                if (shouldStop != null && shouldStop.getAsBoolean()) {
                    return;
                }
                if (monitor != null && monitor.isCancelled()) {
                    return;
                }
                try {
                    applyAndStoreInference(program, address, inference, monitor);
                } catch (Exception e) {
                    Msg.warn(this, "Error applying inference at " + address + ": " + e.getMessage(), e);
                    // Continue with other inferences
                }
            }
        });
    }

    private void applyAndStoreInference(Program program, Address address, Inference inference, TaskMonitor monitor) {
        applyInference(program, address, inference, monitor);

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
        } else if (actual instanceof ParameterType) {
            return "parameter_type";
        } else if (actual instanceof ReturnType) {
            return "return_type";
        } else if (actual instanceof SwiftFunction) {
            return "swift_function";
        } else if (actual instanceof StructDefinition) {
            return "struct_definition";
        } else if (actual instanceof NotSwift) {
            return "not_swift";
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
        } else if (actual instanceof ParameterType) {
            return ((ParameterType) actual).getAddress();
        } else if (actual instanceof ReturnType) {
            return ((ReturnType) actual).getAddress();
        } else if (actual instanceof SwiftFunction) {
            return ((SwiftFunction) actual).getAddress();
        } else if (actual instanceof NotSwift) {
            return ((NotSwift) actual).getAddress();
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
    private void applyInference(Program program, Address address, Inference inference, TaskMonitor monitor) {
        Object actual = inference.getActualInstance();
        
        if (actual instanceof FunctionOverview) {
            applyFunctionOverview(program, address, (FunctionOverview) actual);
        } else if (actual instanceof Name) {
            Msg.debug(this, "Applying name inference at " + address);
            applyName(program, address, (Name) actual);
        } else if (actual instanceof VariablesMapping) {
            VariablesMapping mapping = (VariablesMapping) actual;
            Msg.info(this, "Applying variables_mapping at " + address + " entries="
                + (mapping.getVariablesMapping() != null ? mapping.getVariablesMapping().size() : 0)
                + " keys=" + (mapping.getVariablesMapping() != null ? mapping.getVariablesMapping().keySet() : java.util.Collections.emptySet()));
            applyVariablesMapping(program, address, (VariablesMapping) actual);
        } else if (actual instanceof ParametersMapping) {
            applyParametersMapping(program, address, (ParametersMapping) actual);
        } else if (actual instanceof StructDefinition) {
            applyStructDefinition(program, (StructDefinition) actual);
        } else if (actual instanceof ParameterType) {
            applyParameterType(program, address, (ParameterType) actual);
        } else if (actual instanceof ReturnType) {
            applyReturnType(program, address, (ReturnType) actual, monitor);
        } else if (actual instanceof NotSwift) {
            Msg.debug(this, "Received not_swift inference at " + ((NotSwift) actual).getAddress());
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
        String addressLabel = address != null ? address.toString() : "<global>";
        Object type = actual.get("type");
        if (type == null) {
            Msg.warn(this, "Unknown inference map with no type at " + addressLabel);
            return;
        }
        String typeValue = String.valueOf(type);
        if ("name".equals(typeValue)) {
            Object nameValue = actual.get("name");
            if (nameValue != null && address != null) {
                Msg.debug(this, "Applying map-based name inference at " + address);
                applyNameString(program, address, String.valueOf(nameValue));
            }
            return;
        }
        if ("variables".equals(typeValue) || "variables_mapping".equals(typeValue)) {
            // CANDIDATE_REMOVAL: compatibility fallback for map-shaped variables payloads.
            // Current runtime logs show typed VariablesMapping flow and no observed hits for
            // "Applying map-based variables_mapping". Keep for safety until server payload
            // contract is confirmed stable, then consider removing this branch.
            if (address == null) {
                Msg.warn(this, "Skipping map-based variables mapping at " + addressLabel + ": missing address");
                return;
            }
            Object mappingValue = actual.get("variables_mapping");
            if (!(mappingValue instanceof java.util.Map<?, ?>)) {
                Msg.warn(this, "Skipping map-based variables mapping at " + addressLabel
                    + ": missing variables_mapping payload");
                return;
            }
            VariablesMapping mapped = new VariablesMapping();
            mapped.setAddress(address.toString());
            Map<String, String> converted = new HashMap<>();
            for (Map.Entry<?, ?> entry : ((java.util.Map<?, ?>) mappingValue).entrySet()) {
                if (entry.getKey() == null || entry.getValue() == null) {
                    continue;
                }
                converted.put(String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
            }
            mapped.setVariablesMapping(converted);
            Msg.info(this, "Applying map-based variables_mapping at " + address + " entries=" + converted.size()
                + " keys=" + converted.keySet());
            applyVariablesMapping(program, address, mapped);
            return;
        }
        Msg.warn(this, "Unhandled inference map type '" + typeValue + "' at " + addressLabel);
    }

    private void applyStructDefinition(Program program, StructDefinition structDefinition) {
        structInferenceApplier.applyStructDefinition(program, structDefinition);
    }

    private void applyParameterType(Program program, Address address, ParameterType parameterType) {
        if (address == null) {
            return;
        }
        Function function = getFunctionAtAddress(program, address);
        if (function == null) {
            return;
        }
        FunctionTypeInferenceApplier.ApplyResult result =
            functionTypeInferenceApplier.applyParameterType(program, address, parameterType, function, 0);
        if (result == FunctionTypeInferenceApplier.ApplyResult.APPLIED) {
            typeChangedAddresses.add(address);
        }
    }

    private void applyReturnType(Program program, Address address, ReturnType returnType, TaskMonitor monitor) {
        if (address == null) {
            return;
        }
        Function function = getFunctionAtAddress(program, address);
        if (function == null) {
            return;
        }
        FunctionTypeInferenceApplier.ApplyResult result =
            functionTypeInferenceApplier.applyReturnType(program, address, returnType, function, 0, monitor);
        if (result == FunctionTypeInferenceApplier.ApplyResult.APPLIED) {
            typeChangedAddresses.add(address);
        }
    }

    public void retryDeferredTypeInferences(Program program) {
        retryDeferredTypeInferences(program, TaskMonitor.DUMMY);
    }

    public void retryDeferredTypeInferences(Program program, TaskMonitor monitor) {
        List<InferenceStorage.DeferredTypeInferenceRecord> deferredRecords =
            new ArrayList<>(inferenceStorage.getDeferredTypeInferences());
        if (deferredRecords.isEmpty()) {
            return;
        }

        for (InferenceStorage.DeferredTypeInferenceRecord record : deferredRecords) {
            if (record == null || record.getId() == null) {
                continue;
            }
            inferenceStorage.removeDeferredTypeInference(record.getId());
            int currentAttempts = Math.max(0, record.getAttempts());

            if ("parameter_type".equals(record.getKind()) && record.getParameterType() != null) {
                applyDeferredParameterType(program, record.getParameterType(), currentAttempts);
                continue;
            }
            if ("return_type".equals(record.getKind()) && record.getReturnType() != null) {
                applyDeferredReturnType(program, record.getReturnType(), currentAttempts, monitor);
            }
        }
    }

    private void applyDeferredParameterType(Program program, ParameterType inference, int currentAttempts) {
        Address address = parseAddress(inference.getAddress(), program);
        if (address == null) {
            requeueDeferredParameterType(inference, currentAttempts + 1);
            return;
        }
        Function function = getFunctionAtAddress(program, address);
        if (function == null) {
            requeueDeferredParameterType(inference, currentAttempts + 1);
            return;
        }

        FunctionTypeInferenceApplier.ApplyResult result = functionTypeInferenceApplier.applyParameterType(
            program,
            address,
            inference,
            function,
            currentAttempts
        );
        if (result == FunctionTypeInferenceApplier.ApplyResult.APPLIED) {
            typeChangedAddresses.add(address);
        }
        if (result == FunctionTypeInferenceApplier.ApplyResult.DEFERRED
            && currentAttempts + 1 >= MAX_DEFERRED_RETRY_ATTEMPTS) {
            inferenceStorage.removeDeferredTypeInference(inferenceStorage.buildDeferredParameterInferenceId(inference));
            Msg.warn(this, "Dropping deferred parameter_type after max retries at " + inference.getAddress()
                + " index " + inference.getParameterIndex());
        }
        if (result == FunctionTypeInferenceApplier.ApplyResult.SKIPPED) {
            requeueDeferredParameterType(inference, currentAttempts + 1);
        }
    }

    private void applyDeferredReturnType(
        Program program,
        ReturnType inference,
        int currentAttempts,
        TaskMonitor monitor
    ) {
        Address address = parseAddress(inference.getAddress(), program);
        if (address == null) {
            requeueDeferredReturnType(inference, currentAttempts + 1);
            return;
        }
        Function function = getFunctionAtAddress(program, address);
        if (function == null) {
            requeueDeferredReturnType(inference, currentAttempts + 1);
            return;
        }

        FunctionTypeInferenceApplier.ApplyResult result = functionTypeInferenceApplier.applyReturnType(
            program,
            address,
            inference,
            function,
            currentAttempts,
            monitor
        );
        if (result == FunctionTypeInferenceApplier.ApplyResult.APPLIED) {
            typeChangedAddresses.add(address);
        }
        if (result == FunctionTypeInferenceApplier.ApplyResult.DEFERRED
            && currentAttempts + 1 >= MAX_DEFERRED_RETRY_ATTEMPTS) {
            inferenceStorage.removeDeferredTypeInference(inferenceStorage.buildDeferredReturnInferenceId(inference));
            Msg.warn(this, "Dropping deferred return_type after max retries at " + inference.getAddress());
        }
        if (result == FunctionTypeInferenceApplier.ApplyResult.SKIPPED) {
            requeueDeferredReturnType(inference, currentAttempts + 1);
        }
    }

    private void requeueDeferredParameterType(ParameterType inference, int attempts) {
        if (attempts >= MAX_DEFERRED_RETRY_ATTEMPTS) {
            Msg.warn(this, "Dropping deferred parameter_type after max retries at " + inference.getAddress()
                + " index " + inference.getParameterIndex());
            return;
        }
        inferenceStorage.enqueueDeferredParameterType(inference, attempts);
    }

    private void requeueDeferredReturnType(ReturnType inference, int attempts) {
        if (attempts >= MAX_DEFERRED_RETRY_ATTEMPTS) {
            Msg.warn(this, "Dropping deferred return_type after max retries at " + inference.getAddress());
            return;
        }
        inferenceStorage.enqueueDeferredReturnType(inference, attempts);
    }

    /**
     * Apply struct definitions directly. Reconciliation (ordering, naming,
     * cycle detection) is handled server-side; the client trusts the order
     * the inferences arrive in.
     */
    private void applyStructDefinitions(Program program, List<Inference> inferences) {
        List<StructDefinition> structDefinitions = new ArrayList<>();
        for (Inference inference : inferences) {
            Object actual = inference.getActualInstance();
            if (actual instanceof StructDefinition) {
                StructDefinition definition = (StructDefinition) actual;
                if (definition.getId() != null) {
                    structDefinitions.add(definition);
                    inferenceStorage.storeStructDefinition(definition);
                }
            }
        }
        if (structDefinitions.isEmpty()) {
            return;
        }
        TransactionUtils.runInTransaction(program, "Zenyard: Apply struct definitions", () -> {
            for (StructDefinition definition : structDefinitions) {
                structInferenceApplier.applyStructDefinition(program, definition);
            }
        });
    }

    private Function getFunctionAtAddress(Program program, Address address) {
        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionAt(address);
        if (function == null) {
            Msg.warn(this, "No function at address " + address);
        }
        return function;
    }
    
    /**
     * Apply function overview inference.
     */
    private void applyFunctionOverview(Program program, Address address, FunctionOverview overview) {
        Function function = getFunctionAtAddress(program, address);
        if (function == null) {
            return;
        }
        
        // Check if user has defined a comment
        if (hasUserDefinedComment(program, function)) {
            return; // Don't override user comments
        }

        // Normalize stale FUN_<addr> references to the current symbol names before writing.
        String normalizedOverview = normalizeOverviewFunctionNames(program, overview.getFullDescription());
        overviewAnnotator.addOverview(program, function, normalizedOverview);
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

        nameToApply = resolveUniqueFunctionName(program, address, nameToApply);

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
     * Resolve a unique function name. If another function already has the given name
     * at a different address, rename conflicting functions and this function to Ghidra's
     * standard address-appended format (name@addr) so all colliding functions are
     * disambiguated consistently.
     */
    private String resolveUniqueFunctionName(Program program, Address ourAddress, String baseName) {
        SymbolTable symbolTable = program.getSymbolTable();
        Iterator<Symbol> existing = symbolTable.getSymbols(baseName);
        List<Symbol> conflictingFunctions = new ArrayList<>();
        while (existing.hasNext()) {
            Symbol s = existing.next();
            if (s.getSymbolType() != SymbolType.FUNCTION) {
                continue;
            }
            Address symAddr = s.getAddress();
            if (symAddr != null && !symAddr.equals(ourAddress)) {
                conflictingFunctions.add(s);
            }
        }
        if (conflictingFunctions.isEmpty()) {
            return baseName;
        }

        for (Symbol conflict : conflictingFunctions) {
            Address conflictAddress = conflict.getAddress();
            if (conflictAddress == null) {
                continue;
            }
            String disambiguatedConflictName = SymbolUtilities.getAddressAppendedName(baseName, conflictAddress);
            String currentConflictName = conflict.getName();
            if (disambiguatedConflictName.equals(currentConflictName)) {
                continue;
            }
            try {
                conflict.setName(disambiguatedConflictName, SourceType.ANALYSIS);
                Msg.info(this, "Resolved duplicate name '" + baseName + "' for existing function at "
                    + conflictAddress + " -> " + disambiguatedConflictName);
            } catch (Exception e) {
                Msg.warn(this, "Failed to disambiguate existing function name '" + baseName + "' at "
                    + conflictAddress + ": " + e.getMessage());
            }
        }

        String uniqueName = SymbolUtilities.getAddressAppendedName(baseName, ourAddress);
        Msg.info(this, "Resolved duplicate name '" + baseName + "' to '" + uniqueName
            + "' at " + ourAddress);
        return uniqueName;
    }
    
    /**
     * Apply variables mapping inference.
     */
    private void applyVariablesMapping(Program program, Address address, VariablesMapping mapping) {
        if (variableRenamer != null) {
            variableRenamer.applyVariablesMapping(program, address, mapping);
            return;
        }
        Function function = getFunctionAtAddress(program, address);
        if (function == null) {
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
                ZenyardConstants.DECOMPILER_TIMEOUT_SECONDS,
                TaskMonitor.DUMMY
            );
            
            if (!results.decompileCompleted()) {
                String errMsg = results.getErrorMessage() != null ? results.getErrorMessage() : "Unknown error";
                Msg.warn(this, "Skipping variables_mapping at " + address + ": decompilation failed - " + errMsg);
                return;
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
     * Uses in-applier logic so all key formats are supported (param_1, arg1, original name, 0/1-based index).
     * ParameterRenamer is not used here because it only accepts integer keys and would skip other formats.
     */
    private void applyParametersMapping(Program program, Address address, ParametersMapping mapping) {
        Function function = getFunctionAtAddress(program, address);
        if (function == null) {
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
                    ZenyardConstants.DECOMPILER_TIMEOUT_SECONDS,
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
     * Check if function has a user-defined comment (so we should not overwrite with inferred overview).
     * We never set function comment; we only set the plate comment at the function entry.
     * - Function comment: any non-empty value is user-defined.
     * - Plate comment at entry: user-defined unless it matches a stored FunctionOverview inference.
     */
    private boolean hasUserDefinedComment(Program program, Function function) {
        // We never set function.getComment(); any non-empty function comment is from the user
        String functionComment = function.getComment();
        if (functionComment != null && !functionComment.trim().isEmpty()) {
            return true;
        }

        // Check plate comment at function entry (what we set via overviewAnnotator.addOverview)
        Address entryPoint = function.getEntryPoint();
        String plateComment = program.getListing().getComment(CommentType.PLATE, entryPoint);
        if (plateComment == null || plateComment.trim().isEmpty()) {
            return false; // no comment to protect
        }

        // If we have a stored FunctionOverview inference for this address and the plate comment
        // matches the stored full_description, then this comment was inferred (we can overwrite).
        String inferenceId = entryPoint.toString() + ".function_overview";
        InferenceStorage.InferenceData stored = inferenceStorage.getInference(inferenceId);
        if (stored == null || stored.getData() == null) {
            return true; // no stored inference -> plate comment is user-defined
        }
        Object storedDesc = stored.getData().get("full_description");
        String storedFullDescription = storedDesc != null ? String.valueOf(storedDesc) : null;
        if (isStoredOverviewEquivalentForComment(
            plateComment,
            storedFullDescription,
            text -> normalizeOverviewFunctionNames(program, text)
        )) {
            return false; // normalized stored text still matches -> inferred, we may overwrite
        }
        return true; // stored but different -> user edited or other source; treat as user-defined
    }

    private void refreshFunctionOverviewInferences(Program program, List<Inference> inferences) {
        if (program == null || inferences == null || inferences.isEmpty()) {
            return;
        }
        TransactionUtils.runInTransaction(program, "Zenyard: Refresh function overviews", () -> {
            for (Inference inference : inferences) {
                if (!(inference.getActualInstance() instanceof FunctionOverview)) {
                    continue;
                }
                FunctionOverview overview = (FunctionOverview) inference.getActualInstance();
                Address overviewAddress = parseAddress(overview.getAddress(), program);
                if (overviewAddress == null) {
                    continue;
                }
                applyFunctionOverview(program, overviewAddress, overview);
            }
        });
    }

    private String normalizeOverviewFunctionNames(Program program, String overviewText) {
        if (overviewText == null || overviewText.isEmpty() || program == null) {
            return overviewText;
        }
        return normalizeOverviewFunctionNames(overviewText, token -> resolveOverviewFunctionToken(program, token));
    }

    static String normalizeOverviewFunctionNames(String overviewText, UnaryOperator<String> tokenResolver) {
        if (overviewText == null || overviewText.isEmpty() || tokenResolver == null) {
            return overviewText;
        }
        Matcher matcher = FUN_TOKEN_PATTERN.matcher(overviewText);
        StringBuffer normalized = new StringBuffer();
        while (matcher.find()) {
            String tokenAddress = matcher.group(1);
            String resolvedName = tokenResolver.apply(tokenAddress);
            if (resolvedName == null || resolvedName.isEmpty()) {
                matcher.appendReplacement(normalized, Matcher.quoteReplacement(matcher.group(0)));
            } else {
                matcher.appendReplacement(normalized, Matcher.quoteReplacement(resolvedName));
            }
        }
        matcher.appendTail(normalized);
        return normalized.toString();
    }

    static boolean isStoredOverviewEquivalentForComment(
        String plateComment,
        String storedFullDescription,
        UnaryOperator<String> normalizer
    ) {
        if (plateComment == null || plateComment.trim().isEmpty() || storedFullDescription == null) {
            return false;
        }
        if (storedFullDescription.equals(plateComment)) {
            return true;
        }
        if (normalizer == null) {
            return false;
        }
        String normalizedStored = normalizer.apply(storedFullDescription);
        return normalizedStored != null && normalizedStored.equals(plateComment);
    }

    private String resolveOverviewFunctionToken(Program program, String tokenAddress) {
        Address parsedAddress = parseAddress(tokenAddress, program);
        if (parsedAddress == null) {
            return null;
        }
        Function referencedFunction = program.getFunctionManager().getFunctionAt(parsedAddress);
        if (referencedFunction != null && referencedFunction.getName() != null
            && !referencedFunction.getName().isEmpty()) {
            return referencedFunction.getName();
        }
        Symbol symbol = program.getSymbolTable().getPrimarySymbol(parsedAddress);
        if (symbol != null && symbol.getName() != null && !symbol.getName().isEmpty()) {
            return symbol.getName();
        }
        return null;
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
            data.put("full_description", overview.getFullDescription());
        } else if (actual instanceof Name) {
            Name name = (Name) actual;
            data.put("name", name.getName());
        } else if (actual instanceof VariablesMapping) {
            VariablesMapping mapping = (VariablesMapping) actual;
            data.put("variables_mapping", mapping.getVariablesMapping());
        } else if (actual instanceof ParametersMapping) {
            ParametersMapping mapping = (ParametersMapping) actual;
            data.put("parameters_mapping", mapping.getParametersMapping());
        } else if (actual instanceof ParameterType) {
            ParameterType parameterType = (ParameterType) actual;
            data.put("parameter_index", parameterType.getParameterIndex());
            data.put("type_annotation", parameterType.getTypeAnnotation());
            java.util.UUID parameterStructId = parameterType.getStructId();
            data.put("struct_id", parameterStructId != null ? parameterStructId.toString() : null);
        } else if (actual instanceof ReturnType) {
            ReturnType returnType = (ReturnType) actual;
            data.put("type_annotation", returnType.getTypeAnnotation());
            java.util.UUID returnStructId = returnType.getStructId();
            data.put("struct_id", returnStructId != null ? returnStructId.toString() : null);
        } else if (actual instanceof StructDefinition) {
            StructDefinition structDefinition = (StructDefinition) actual;
            data.put("id", structDefinition.getId() != null ? structDefinition.getId().toString() : null);
            data.put("name", structDefinition.getName());
            List<Map<String, Object>> serializedFields = new ArrayList<>();
            if (structDefinition.getFieldDefinitions() != null) {
                for (FieldDefinition field : structDefinition.getFieldDefinitions()) {
                    if (field == null) {
                        continue;
                    }
                    Map<String, Object> fieldData = new HashMap<>();
                    fieldData.put("suggested_field_name", field.getSuggestedFieldName());
                    fieldData.put("field_type", field.getFieldType());
                    fieldData.put("field_offset", field.getFieldOffset());
                    java.util.UUID fieldStructId = field.getStructId();
                    fieldData.put("struct_id", fieldStructId != null ? fieldStructId.toString() : null);
                    serializedFields.add(fieldData);
                }
            }
            data.put("field_definitions", serializedFields);
            data.put("merged_from", structDefinition.getMergedFrom());
        } else if (actual instanceof NotSwift) {
            NotSwift notSwift = (NotSwift) actual;
            data.put("reason", notSwift.getReason() != null ? notSwift.getReason().toString() : null);
        } else if (actual instanceof SwiftFunction) {
            SwiftFunction swift = (SwiftFunction) actual;
            data.put("swift_function", gson.toJsonTree(swift).getAsJsonObject());
        } else {
            // Generic serialization for unknown types
            data.put("raw_data", gson.toJsonTree(inference).getAsJsonObject());
        }
        
        return data;
    }

    private int getInferencePriority(Inference inference) {
        String type = getInferenceType(inference);
        if ("struct_definition".equals(type)) {
            return 0;
        }
        // Apply variable/parameter naming before type updates to avoid
        // rename-key drift when type propagation changes decompiler temp names.
        if ("variables".equals(type) || "variables_mapping".equals(type)
                || "params".equals(type) || "parameters_mapping".equals(type)) {
            return 1;
        }
        if ("name".equals(type)) {
            return 2;
        }
        if ("parameter_type".equals(type) || "return_type".equals(type)) {
            return 3;
        }
        if ("function_overview".equals(type)) {
            return 4;
        }
        return 5;
    }

    private boolean isFunctionPrototypeInference(Inference inference) {
        if (inference == null) {
            return false;
        }
        Object actual = inference.getActualInstance();
        if (actual instanceof ParameterType || actual instanceof ReturnType) {
            return true;
        }
        if (actual instanceof java.util.Map<?, ?>) {
            Object type = ((java.util.Map<?, ?>) actual).get("type");
            if (type != null) {
                String typeValue = String.valueOf(type);
                return "parameter_type".equals(typeValue) || "return_type".equals(typeValue);
            }
        }
        return false;
    }

    private String getGlobalInferenceId(Inference inference, String inferenceType) {
        Object actual = inference.getActualInstance();
        if (actual instanceof StructDefinition) {
            StructDefinition structDefinition = (StructDefinition) actual;
            if (structDefinition.getId() != null) {
                return "global." + structDefinition.getId().toString() + "." + inferenceType;
            }
        }
        return "global." + inferenceType;
    }
}

