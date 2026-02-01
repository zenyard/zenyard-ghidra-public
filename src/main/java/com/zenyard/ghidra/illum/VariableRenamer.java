package com.zenyard.ghidra.illum;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.zenyard.ghidra.api.generated.model.VariablesMapping;
import com.zenyard.ghidra.storage.InferenceStorage;
import com.zenyard.ghidra.util.ZenyardConstants;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Applies variable name mappings for a function.
 */
public class VariableRenamer {
    private final InferenceStorage inferenceStorage;

    public VariableRenamer(InferenceStorage inferenceStorage) {
        this.inferenceStorage = inferenceStorage;
    }

    public void applyVariablesMapping(Program program, Address address, VariablesMapping mapping) {
        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionAt(address);

        if (function == null) {
            Msg.warn(this, "No function at address " + address);
            return;
        }

        DecompilerManager decompilerManager = new DecompilerManager();
        DecompileResults results = decompilerManager.decompileFunction(
            program,
            function,
            ZenyardConstants.DECOMPILER_TIMEOUT_SECONDS,
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

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        Iterator<HighSymbol> localSymbolsIter = localSymbolMap.getSymbols();
        List<HighSymbol> localSymbols = new ArrayList<>();
        localSymbolsIter.forEachRemaining(localSymbols::add);

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

        VariablesMapping lastMapping = inferenceStorage.getLastVariablesMapping(address);
        Set<String> lastInferredNames = new HashSet<>();
        if (lastMapping != null) {
            lastInferredNames.addAll(lastMapping.getVariablesMapping().values());
        }

        Map<String, String> renames = new HashMap<>();
        Map<String, String> variablesMapping = mapping.getVariablesMapping();
        for (Map.Entry<String, String> entry : variablesMapping.entrySet()) {
            String originalName = entry.getKey();
            String newName = entry.getValue();

            HighSymbol symbol = variableNameToSymbol.get(originalName);
            if (symbol == null) {
                continue;
            }

            HighVariable var = symbol.getHighVariable();
            if (var == null) {
                continue;
            }

                String currentType = var.getDataType() != null ? var.getDataType().getName() : "unknown";
                Msg.debug(this, "Variable mapping: " + originalName + " -> " + newName
                    + " (currentType=" + currentType + ")");

            boolean isDummy = var.getName().startsWith("uVar")
                || var.getName().startsWith("local_")
                || var.getName().matches("^[a-z]\\d+$")
                || InferenceNameUtils.isPlaceholderName(var.getName());

            if (isDummy || lastInferredNames.contains(originalName)) {
                renames.put(originalName, newName);
            }
        }

        boolean localsCommitted = false;
        for (Map.Entry<String, String> rename : renames.entrySet()) {
            String fromName = rename.getKey();
            String toName = rename.getValue();

            HighSymbol symbol = variableNameToSymbol.get(fromName);
            if (symbol == null) {
                continue;
            }

            try {
                if (InferenceNameUtils.isPlaceholderName(toName)) {
                    Msg.debug(this, "Skipping rename for " + fromName + " at " + address
                        + ": placeholder name " + toName);
                    continue;
                }
                String nameToApply = InferenceNameUtils.isValidName(toName) ? toName : "_" + toName;
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

                    LocalVariable localVar = InferenceNameUtils.findLocalVariableByStorage(function, storage);
                    if (localVar == null) {
                        Msg.debug(this, "Skipping rename for " + fromName + " at " + address
                            + ": cannot resolve local variable");
                        continue;
                    }

                    localVar.setName(nameToApply, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                    localsCommitted = true;
                }
            } catch (DuplicateNameException | InvalidInputException e) {
                Msg.debug(this, "Rename conflict for " + fromName + " -> " + toName + ": " + e.getMessage());
            } catch (Exception e) {
                Msg.warn(this, "Failed to rename variable " + fromName + ": " + e.getMessage(), e);
            }
        }

        if (!localsCommitted) {
            Msg.debug(this, "No local variable renames applied for " + address);
        }
    }
}
