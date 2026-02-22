package com.zenyard.ghidra.illum;

import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import com.zenyard.ghidra.api.generated.model.ParameterType;
import com.zenyard.ghidra.api.generated.model.ReturnType;
import com.zenyard.ghidra.storage.InferenceStorage;
import com.zenyard.ghidra.util.ZenyardConstants;
import com.zenyard.ghidra.util.TransactionUtils;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import java.util.function.BooleanSupplier;

/**
 * Applies parameter and return type inferences to function signatures.
 */
public class FunctionTypeInferenceApplier {

    private final InferenceStorage inferenceStorage;
    private final StructInferenceApplier structInferenceApplier;

    public FunctionTypeInferenceApplier(
        InferenceStorage inferenceStorage,
        StructInferenceApplier structInferenceApplier
    ) {
        this.inferenceStorage = inferenceStorage;
        this.structInferenceApplier = structInferenceApplier;
    }

    public enum ApplyResult {
        APPLIED,
        DEFERRED,
        SKIPPED
    }

    public ApplyResult applyParameterType(
        Program program,
        Address address,
        ParameterType inference,
        Function function,
        int deferredAttempts
    ) {
        if (program == null || address == null || inference == null || function == null) {
            return ApplyResult.SKIPPED;
        }

        int index = inference.getParameterIndex();
        List<Parameter> formalParameters = getFormalParameters(function);
        if (index < 0 || index >= formalParameters.size()) {
            Msg.info(this, "Skipping parameter_type at " + address + ": index out of range " + index);
            return ApplyResult.SKIPPED;
        }
        DataType resolved = structInferenceApplier.resolveInferenceDataType(
            program,
            inference.getTypeAnnotation(),
            inference.getStructId()
        );
        if (resolved == null) {
            Msg.warn(this, "Could not resolve parameter type '" + inference.getTypeAnnotation()
                + "' at " + address + " index " + index + "; deferring");
            inferenceStorage.enqueueDeferredParameterType(inference, deferredAttempts + 1);
            return ApplyResult.DEFERRED;
        }

        try {
            applyUpdatedSignature(function, index, resolved, null);
            inferenceStorage.markInferredParameterType(address, index, resolved.getPathName());
            List<Parameter> refreshedFormalParameters = getFormalParameters(function);
            DataType appliedType = index < refreshedFormalParameters.size()
                ? refreshedFormalParameters.get(index).getFormalDataType()
                : null;
            verifyAppliedType(
                "parameter",
                address,
                "param_" + index,
                resolved,
                appliedType,
                inference.getStructId()
            );
            Msg.info(this, "Applied parameter_type at " + address + " index " + index
                + " -> " + (appliedType != null ? appliedType.getDisplayName() : resolved.getDisplayName()));
            return ApplyResult.APPLIED;
        } catch (InvalidInputException e) {
            Msg.warn(this, "Failed applying parameter type at " + address + ": " + e.getMessage());
            return ApplyResult.SKIPPED;
        }
    }

    public ApplyResult applyReturnType(
        Program program,
        Address address,
        ReturnType inference,
        Function function,
        int deferredAttempts,
        TaskMonitor monitor
    ) {
        if (program == null || address == null || inference == null || function == null) {
            return ApplyResult.SKIPPED;
        }

        DataType resolved = structInferenceApplier.resolveInferenceDataType(
            program,
            inference.getTypeAnnotation(),
            inference.getStructId()
        );
        if (resolved == null) {
            Msg.warn(this, "Could not resolve return type '" + inference.getTypeAnnotation() + "' at " + address
                + "; deferring");
            inferenceStorage.enqueueDeferredReturnType(inference, deferredAttempts + 1);
            return ApplyResult.DEFERRED;
        }

        try {
            applyUpdatedSignature(function, -1, null, resolved);
            // applyReturnType is always called from within a transaction (InferenceApplier),
            // so we avoid starting another one here.
            propagateReturnTypeToReturnedLocal(function, resolved, monitor, false);
            inferenceStorage.markInferredReturnType(address, resolved.getPathName());
            DataType appliedType = function.getReturnType();
            verifyAppliedType(
                "return",
                address,
                "return",
                resolved,
                appliedType,
                inference.getStructId()
            );
            Msg.info(this, "Applied return_type at " + address + " -> "
                + (appliedType != null ? appliedType.getDisplayName() : resolved.getDisplayName()));
            return ApplyResult.APPLIED;
        } catch (InvalidInputException e) {
            Msg.warn(this, "Failed applying return type at " + address + ": " + e.getMessage());
            return ApplyResult.SKIPPED;
        }
    }

    private void verifyAppliedType(
        String typeKind,
        Address address,
        String slot,
        DataType expected,
        DataType actual,
        java.util.UUID structId
    ) {
        String expectedPath = expected != null ? expected.getPathName() : null;
        String actualPath = actual != null ? actual.getPathName() : null;
        if (expectedPath != null && expectedPath.equals(actualPath)) {
            return;
        }
        Msg.warn(this, "Post-apply " + typeKind + " mismatch at " + address + " slot=" + slot
            + " expected=" + expectedPath + " actual=" + actualPath + " struct_id="
            + (structId != null ? structId : "null"));
    }

    private List<Parameter> getFormalParameters(Function function) {
        List<Parameter> formal = new ArrayList<>();
        for (Parameter parameter : function.getParameters()) {
            if (!parameter.isAutoParameter()) {
                formal.add(parameter);
            }
        }
        return formal;
    }

    private void applyUpdatedSignature(
        Function function,
        int updatedParameterIndex,
        DataType parameterType,
        DataType returnType
    ) throws InvalidInputException {
        Program program = function.getProgram();
        List<Variable> updatedParams = new ArrayList<>();
        List<Parameter> formalParameters = getFormalParameters(function);
        for (int i = 0; i < formalParameters.size(); i++) {
            Parameter parameter = formalParameters.get(i);
            DataType effectiveType = updatedParameterIndex == i && parameterType != null
                ? parameterType
                : parameter.getFormalDataType();
            SourceType effectiveSource = updatedParameterIndex == i && parameterType != null
                ? SourceType.USER_DEFINED
                : parameter.getSource();
            // Use storage-agnostic parameter construction for dynamic storage updates.
            ParameterImpl updated = new ParameterImpl(
                parameter.getName(),
                effectiveType,
                program,
                effectiveSource
            );
            updatedParams.add(updated);
        }

        DataType effectiveReturnType = returnType != null ? returnType : function.getReturnType();
        SourceType effectiveReturnSource = returnType != null ? SourceType.USER_DEFINED : function.getSignatureSource();
        // Use storage-agnostic return construction for dynamic storage updates.
        ParameterImpl updatedReturn = new ParameterImpl(
            function.getReturn().getName(),
            effectiveReturnType,
            program,
            effectiveReturnSource
        );

        try {
            function.updateFunction(
                function.getCallingConventionName(),
                updatedReturn,
                updatedParams,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true,
                SourceType.USER_DEFINED
            );
        } catch (DuplicateNameException e) {
            throw new InvalidInputException("Duplicate parameter name while updating function signature: "
                + e.getMessage());
        }
    }

    private void propagateReturnTypeToReturnedLocal(
        Function function,
        DataType resolvedType,
        TaskMonitor monitor,
        boolean useOwnTransaction
    ) {
        if (function == null || resolvedType == null) {
            return;
        }

        Address entryPoint = function.getEntryPoint();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(function.getProgram());
        try {
            decompiler.setOptions(new DecompileOptions());
            DecompileResults results = decompiler.decompileFunction(
                function,
                ZenyardConstants.DECOMPILER_TIMEOUT_SECONDS,
                monitor != null ? monitor : TaskMonitor.DUMMY
            );
            if (!results.decompileCompleted()) {
                Msg.warn(this, "Return-type local propagation: decompilation failed for "
                    + entryPoint);
                return;
            }

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.warn(this, "Return-type local propagation: no HighFunction for "
                    + entryPoint);
                return;
            }

            Set<HighSymbol> returnedLocalSymbols = findReturnedLocalSymbols(highFunction);

            if (returnedLocalSymbols.isEmpty()) {
                Msg.info(this, "Return-type local propagation: no returned locals found for "
                    + entryPoint);
                return;
            }

            // Deduplicate symbols that map to the same storage address.
            // The decompiler may produce multiple HighSymbol instances (e.g.
            // from phi-nodes across code paths) that all correspond to the
            // same underlying local variable.
            Map<Address, HighSymbol> uniqueByStorage = new HashMap<>();
            for (HighSymbol sym : returnedLocalSymbols) {
                HighVariable hv = sym.getHighVariable();
                if (hv == null) {
                    continue;
                }
                Varnode rep = hv.getRepresentative();
                if (rep != null) {
                    uniqueByStorage.putIfAbsent(rep.getAddress(), sym);
                }
            }

            if (uniqueByStorage.isEmpty()) {
                Msg.info(this, "Return-type local propagation: returned symbols have no "
                    + "representative storage at " + entryPoint);
                return;
            }

            if (uniqueByStorage.size() != 1) {
                List<String> symbolNames = new ArrayList<>();
                for (HighSymbol sym : uniqueByStorage.values()) {
                    symbolNames.add(sym.getName());
                }
                Msg.info(this, "Return-type local propagation: found "
                    + uniqueByStorage.size() + " distinct returned locals at "
                    + entryPoint + "; skipping (symbols: " + symbolNames + ")");
                return;
            }

            HighSymbol symbol = uniqueByStorage.values().iterator().next();
            Runnable update = () -> {
                try {
                    HighFunctionDBUtil.updateDBVariable(
                        symbol,
                        symbol.getName(),
                        resolvedType,
                        SourceType.USER_DEFINED
                    );
                    inferenceStorage.markReturnTypeLocalPropagated(entryPoint);
                } catch (Exception e) {
                    // Runnable cannot throw checked exceptions; escalate so the surrounding
                    // transaction can be aborted cleanly.
                    throw new RuntimeException(e);
                }
            };
            if (useOwnTransaction) {
                // Keep the transaction short: decompile outside, commit only the DB update + marker.
                TransactionUtils.runInTransaction(
                    function.getProgram(),
                    "Zenyard: Return type local propagation",
                    update
                );
            } else {
                update.run();
            }
            Msg.info(this, "Propagated return type " + resolvedType.getDisplayName()
                + " to local '" + symbol.getName() + "' at " + entryPoint);
        } catch (Exception e) {
            Msg.warn(this, "Failed return-type local propagation for " + entryPoint
                + ": " + e.getMessage());
        } finally {
            decompiler.closeProgram();
        }
    }

    private Set<HighSymbol> findReturnedLocalSymbols(HighFunction highFunction) {
        Set<Varnode> returnedValueNodes = new HashSet<>();
        Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps();
        while (pcodeOps.hasNext()) {
            PcodeOp op = pcodeOps.next();
            if (op.getOpcode() != PcodeOp.RETURN) {
                continue;
            }
            for (int i = 1; i < op.getNumInputs(); i++) {
                Varnode input = op.getInput(i);
                if (input != null) {
                    collectReturnedCandidates(input, returnedValueNodes);
                }
            }
        }

        Set<HighSymbol> matchedSymbols = new HashSet<>();
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            // Skip parameters: on ARM64 the first parameter and return value share
            // register x0, causing address-based matching to incorrectly match the
            // parameter instead of the actual returned local variable.
            if (symbol.getCategoryIndex() >= 0) {
                continue;
            }
            HighVariable variable = symbol.getHighVariable();
            if (variable == null) {
                continue;
            }
            for (Varnode instance : variable.getInstances()) {
                if (instance != null && matchesReturnedNode(instance, returnedValueNodes)) {
                    matchedSymbols.add(symbol);
                    break;
                }
            }
        }
        return matchedSymbols;
    }

    private void collectReturnedCandidates(Varnode root, Set<Varnode> collector) {
        Queue<Varnode> queue = new ArrayDeque<>();
        Set<Varnode> visited = new HashSet<>();
        queue.offer(root);
        while (!queue.isEmpty()) {
            Varnode current = queue.poll();
            if (current == null || !visited.add(current)) {
                continue;
            }
            collector.add(current);
            PcodeOp def = current.getDef();
            if (def == null) {
                continue;
            }
            int opcode = def.getOpcode();
            if (opcode == PcodeOp.COPY
                || opcode == PcodeOp.CAST
                || opcode == PcodeOp.MULTIEQUAL
                || opcode == PcodeOp.PTRSUB
                || opcode == PcodeOp.PTRADD
                || opcode == PcodeOp.INT_ADD
                || opcode == PcodeOp.INT_SEXT
                || opcode == PcodeOp.INT_ZEXT
                || opcode == PcodeOp.SUBPIECE) {
                for (int i = 0; i < def.getNumInputs(); i++) {
                    queue.offer(def.getInput(i));
                }
            }
        }
    }

    private boolean matchesReturnedNode(Varnode candidate, Set<Varnode> returnedNodes) {
        for (Varnode returned : returnedNodes) {
            if (candidate.equals(returned)) {
                return true;
            }
            if (candidate.getAddress().equals(returned.getAddress()) && candidate.getSize() == returned.getSize()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Catch-up propagation: for all functions with pointer-to-struct return types,
     * verify that the returned local variable has the correct type. If not, re-run
     * propagation. This handles functions whose return_type was applied in a previous
     * session (before propagation logic existed or where it failed/targeted the wrong
     * variable, e.g. a parameter sharing the same register as the return value).
     */
    /**
     * @return the set of function entry-point addresses where propagation was performed
     */
    public Set<Address> ensureReturnTypeLocalPropagation(Program program) {
        return ensureReturnTypeLocalPropagation(program, TaskMonitor.DUMMY, () -> false);
    }

    /**
     * Catch-up propagation with cancellation support.
     * <p>
     * This method intentionally avoids holding a long-lived transaction open while
     * decompiling. We only open a short transaction when we actually commit a DB change.
     */
    public Set<Address> ensureReturnTypeLocalPropagation(
        Program program,
        TaskMonitor monitor,
        BooleanSupplier shouldStop
    ) {
        FunctionManager funcManager = program.getFunctionManager();
        Set<Address> propagatedAddresses = new HashSet<>();

        for (Function function : funcManager.getFunctions(true)) {
            if (shouldStop != null && shouldStop.getAsBoolean()) {
                break;
            }
            if (monitor != null && monitor.isCancelled()) {
                break;
            }
            if (program == null || program.isClosed()) {
                break;
            }

            Address entryPoint = function.getEntryPoint();
            // Only do catch-up for functions whose return types were inferred by Zenyard.
            // This avoids a full-program decompiler scan for unrelated functions.
            if (!inferenceStorage.wasReturnTypeInferred(entryPoint)) {
                continue;
            }
            // If we previously succeeded (or at least committed an update), skip. If propagation
            // was incorrect in the past, we should provide an explicit "re-verify" action rather
            // than continuously re-decompiling every inferred function on every batch.
            if (inferenceStorage.wasReturnTypeLocalPropagated(entryPoint)) {
                continue;
            }

            DataType returnType = function.getReturnType();
            if (returnType == null) {
                continue;
            }

            if (!(returnType instanceof ghidra.program.model.data.Pointer)) {
                continue;
            }
            DataType pointedTo = ((ghidra.program.model.data.Pointer) returnType).getDataType();
            if (pointedTo == null || !(pointedTo instanceof ghidra.program.model.data.Structure)) {
                continue;
            }

            try {
                propagateReturnTypeToReturnedLocal(function, returnType, monitor, true);
                propagatedAddresses.add(entryPoint);
            } catch (Exception e) {
                Msg.debug(this, "Catch-up return type propagation failed for "
                    + entryPoint + ": " + e.getMessage());
            }
        }

        if (!propagatedAddresses.isEmpty()) {
            Msg.info(this, "Return type local propagation catch-up: propagated "
                + propagatedAddresses.size() + " functions");
        }
        return propagatedAddresses;
    }

    /**
     * Check if the function's returned local variable already has the expected type.
     * Returns true if propagation is not needed.
     */
    private boolean isReturnedLocalAlreadyTyped(Function function, DataType expectedReturnType) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(function.getProgram());
        try {
            decompiler.setOptions(new DecompileOptions());
            DecompileResults results = decompiler.decompileFunction(
                function,
                ZenyardConstants.DECOMPILER_TIMEOUT_SECONDS,
                TaskMonitor.DUMMY
            );
            if (!results.decompileCompleted()) {
                return false;
            }
            HighFunction hf = results.getHighFunction();
            if (hf == null) {
                return false;
            }

            Set<HighSymbol> returnedLocals = findReturnedLocalSymbols(hf);
            if (returnedLocals.isEmpty()) {
                return true; // No returned locals to type
            }

            for (HighSymbol sym : returnedLocals) {
                HighVariable hv = sym.getHighVariable();
                if (hv == null) {
                    continue;
                }
                DataType currentType = hv.getDataType();
                if (currentType == null) {
                    return false;
                }
                // Compare display names to handle equivalent types across DTMs
                if (!currentType.getDisplayName().equals(expectedReturnType.getDisplayName())) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            decompiler.closeProgram();
        }
    }
}
