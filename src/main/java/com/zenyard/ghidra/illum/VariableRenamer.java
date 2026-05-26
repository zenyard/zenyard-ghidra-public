package com.zenyard.ghidra.illum;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Collections;

import com.zenyard.ghidra.api.AddressHelper;
import com.zenyard.ghidra.api.generated.model.VariablesMapping;
import com.zenyard.ghidra.storage.InferenceStorage;
import com.zenyard.ghidra.storage.InferenceStorage.AppliedVariableRenameRecord;
import com.zenyard.ghidra.storage.InferenceStorage.GlobalDatPendingRenameEntry;
import com.zenyard.ghidra.storage.InferenceStorage.VariableStorageIdentity;
import com.zenyard.ghidra.util.ZenyardConstants;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Applies variable name mappings for a function.
 */
public class VariableRenamer {
    private final InferenceStorage inferenceStorage;
    private final List<PendingVerification> pendingVerifications = new ArrayList<>();

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
            String errMsg = results.getErrorMessage() != null ? results.getErrorMessage() : "Unknown error";
            Msg.warn(this, "Skipping variables_mapping at " + address + ": decompilation failed - " + errMsg);
            return;
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
        Map<String, List<HighSymbol>> variableNameToSymbols = new HashMap<>();
        Map<HighSymbol, VariableStorageIdentity> symbolToIdentity = new HashMap<>();
        Map<String, List<HighSymbol>> identityKeyToSymbols = new HashMap<>();
        for (HighSymbol symbol : localSymbols) {
            HighVariable var = symbol.getHighVariable();
            if (var != null) {
                String varName = var.getName();
                if (varName != null && !varName.isEmpty()) {
                    String scopedVarName = scopedLookupKey(address, varName);
                    variableNameToSymbol.putIfAbsent(scopedVarName, symbol);
                    addUniqueSymbol(variableNameToSymbols, scopedVarName, symbol);
                    String normalizedVarName = InferenceNameUtils.normalizeVariableLookupName(varName);
                    if (normalizedVarName != null && !normalizedVarName.isEmpty()) {
                        String scopedNormalizedVarName = scopedLookupKey(address, normalizedVarName);
                        variableNameToSymbol.putIfAbsent(scopedNormalizedVarName, symbol);
                        addUniqueSymbol(variableNameToSymbols, scopedNormalizedVarName, symbol);
                    }
                }
                ghidra.program.model.pcode.Varnode representative = var.getRepresentative();
                VariableStorageIdentity identity = InferenceNameUtils.toStorageIdentity(representative);
                if (identity != null) {
                    symbolToIdentity.put(symbol, identity);
                    identityKeyToSymbols.computeIfAbsent(identity.asKey(), ignored -> new ArrayList<>()).add(symbol);
                }
            }
        }
        Map<String, VariableStorageIdentity> persistedIdentities = inferenceStorage.getVariableIdentities(address);

        VariablesMapping lastMapping = inferenceStorage.getLastVariablesMapping(address);
        Set<String> lastInferredOriginalNames = new HashSet<>();
        if (lastMapping != null) {
            lastInferredOriginalNames.addAll(lastMapping.getVariablesMapping().keySet());
        }

        List<RenameRequest> renameRequests = new ArrayList<>();
        List<RenameRequest> appliedRenameRequests = new ArrayList<>();
        Map<String, String> appliedRenameTargetsByOriginal = new HashMap<>();
        Map<String, AppliedVariableRenameRecord> appliedRenameRecordsByOriginal = new HashMap<>();
        List<DeferredStackRename> deferredStackRenames = new ArrayList<>();
        List<GlobalRenameRequest> globalRenames = new ArrayList<>();
        Map<String, String> variablesMapping = mapping.getVariablesMapping();
        Msg.debug(this, "VariablesMapping received at " + address + " entries="
            + variablesMapping.size() + " keys=" + variablesMapping.keySet());
        for (Map.Entry<String, String> entry : variablesMapping.entrySet()) {
            String originalName = entry.getKey();
            String newName = entry.getValue();
            String normalizedOriginalName = InferenceNameUtils.normalizeVariableLookupName(originalName);

            SymbolResolution resolution = resolveSymbol(
                address,
                originalName,
                normalizedOriginalName,
                variableNameToSymbol,
                variableNameToSymbols,
                persistedIdentities,
                identityKeyToSymbols
            );
            HighSymbol symbol = resolution.getSymbol();
            Msg.debug(this, "VariablesMapping entry at " + address + ": original=" + originalName
                + ", target=" + newName + ", resolution=" + resolution.getMode());
            if (symbol == null) {
                // Defer stack-offset fallback: stack arrays (e.g. auStack_58 / acStack_58)
                // may not appear in the HighFunction's LocalSymbolMap until after
                // commitLocalNamesToDatabase. Collect them for resolution after the commit.
                Long stackOffset = InferenceNameUtils.extractStackOffset(originalName);
                if (stackOffset != null) {
                    deferredStackRenames.add(new DeferredStackRename(stackOffset, originalName, newName));
                } else if (isGlobalDataLabel(originalName)) {
                    // Global data labels (DAT_*, _DAT_*, PTR_*) are not in the
                    // LocalSymbolMap. Collect them for separate global renaming.
                    globalRenames.add(new GlobalRenameRequest(originalName, newName));
                } else {
                    Msg.info(this, "VariablesMapping unresolved at " + address
                        + ": original=" + originalName + ", target=" + newName);
                }
                continue;
            }

            HighVariable var = symbol.getHighVariable();
            if (var == null) {
                Msg.debug(this, "Skipping rename for " + originalName + " at " + address
                    + ": HighVariable is null for resolved symbol (resolution="
                    + resolution.getMode() + ")");
                continue;
            }

            String currentType = var.getDataType() != null ? var.getDataType().getName() : "unknown";
            Msg.debug(this, "Variable mapping: " + originalName + " -> " + newName
                + " (currentType=" + currentType + ")");

            boolean isDummy = InferenceNameUtils.isAutoGeneratedVariableName(var.getName())
                || InferenceNameUtils.isPlaceholderName(var.getName());
            boolean wasPreviouslyInferred = lastInferredOriginalNames.contains(originalName)
                || (normalizedOriginalName != null && lastInferredOriginalNames.contains(normalizedOriginalName));

            if (isDummy || wasPreviouslyInferred) {
                renameRequests.add(new RenameRequest(
                    originalName,
                    newName,
                    symbol,
                    symbolToIdentity.get(symbol)
                ));
            } else {
                Msg.debug(this, "Skipping rename for " + originalName + " at " + address
                    + ": variable name '" + var.getName()
                    + "' is not auto-generated and not previously inferred");
            }

            VariableStorageIdentity resolvedIdentity = symbolToIdentity.get(symbol);
            if (resolvedIdentity != null) {
                inferenceStorage.storeVariableIdentity(address, originalName, resolvedIdentity);
                if (normalizedOriginalName != null && !normalizedOriginalName.equals(originalName)) {
                    inferenceStorage.storeVariableIdentity(address, normalizedOriginalName, resolvedIdentity);
                }
            }
        }

        // Commit decompiler locals to the database before renaming.
        // Without this, register-based variables (e.g. return values from calls)
        // have no backing LocalVariable and fall through to the volatile
        // renameSymbolInDatabase path whose names don't survive re-decompilation
        // triggered by later type inference changes.
        boolean localsCommitted = false;
        try {
            HighFunctionDBUtil.commitLocalNamesToDatabase(highFunction, SourceType.ANALYSIS);
            localsCommitted = true;
        } catch (Exception e) {
            Msg.info(this, "commitLocalNamesToDatabase at " + address + ": " + e.getMessage());
        }

        for (RenameRequest rename : renameRequests) {
            String fromName = rename.getOriginalName();
            String toName = rename.getTargetName();
            HighSymbol symbol = rename.getSymbol();

            try {
                if (InferenceNameUtils.isPlaceholderName(toName)) {
                    Msg.debug(this, "Skipping rename for " + fromName + " at " + address
                        + ": placeholder name " + toName);
                    continue;
                }
                String nameToApply = InferenceNameUtils.isValidName(toName) ? toName : "_" + toName;
                HighVariable highVar = symbol.getHighVariable();
                if (highVar == null) {
                    Msg.debug(this, "Skipping rename for " + fromName + " at " + address
                        + ": no HighVariable for symbol");
                    continue;
                }
                ghidra.program.model.pcode.Varnode storage = highVar.getRepresentative();
                if (storage == null) {
                    Msg.debug(this, "Skipping rename for " + fromName + " at " + address
                        + ": no representative storage");
                    continue;
                }

                Address storageAddress = storage.getAddress();
                if (storageAddress.isUniqueAddress()) {
                    // Unique-space vars do not have a stable LocalVariable entry, so
                    // rename through the HighSymbol and rely on verification/refresh
                    // to re-apply after later decompilations.
                    boolean renamedUnique = renameSymbolInDatabase(symbol, nameToApply);
                    if (!renamedUnique) {
                        Msg.debug(this, "Skipping rename for " + fromName + " at " + address
                            + ": temporary unique storage and symbol fallback failed");
                        continue;
                    }
                    appliedRenameRequests.add(rename);
                    appliedRenameTargetsByOriginal.put(fromName, nameToApply);
                    addAppliedRenameRecord(appliedRenameRecordsByOriginal, rename, nameToApply);
                    Msg.info(this, "Applied unique-storage rename for " + fromName + " at " + address
                        + " -> " + nameToApply);
                    continue;
                }

                if (!storageAddress.isStackAddress() && !storageAddress.isRegisterAddress()) {
                    Msg.debug(this, "Skipping rename for " + fromName + " at " + address
                        + ": non-local storage " + storageAddress);
                    continue;
                }

                LocalVariable localVar = InferenceNameUtils.findLocalVariableByStorage(function, storage);
                if (localVar == null && !localsCommitted) {
                    // Retry commit if the earlier attempt failed; some variables
                    // may only become visible after partial renames.
                    try {
                        HighFunctionDBUtil.commitLocalNamesToDatabase(highFunction, SourceType.ANALYSIS);
                        localsCommitted = true;
                        localVar = InferenceNameUtils.findLocalVariableByStorage(function, storage);
                    } catch (Exception e) {
                        Msg.debug(this, "Retry commitLocalNamesToDatabase at " + address
                            + ": " + e.getMessage());
                    }
                }
                if (localVar == null) {
                    // Last resort: use HighFunctionDBUtil.updateDBVariable which
                    // creates a database entry if one doesn't exist yet.
                    boolean renamedBySymbol = renameSymbolInDatabase(symbol, nameToApply);
                    if (!renamedBySymbol) {
                        Msg.debug(this, "Skipping rename for " + fromName + " at " + address
                            + ": cannot resolve local variable by storage and symbol fallback failed");
                        continue;
                    }
                    appliedRenameRequests.add(rename);
                    appliedRenameTargetsByOriginal.put(fromName, nameToApply);
                    addAppliedRenameRecord(appliedRenameRecordsByOriginal, rename, nameToApply);
                    Msg.info(this, "Applied symbol-level rename for " + fromName + " at " + address
                        + " -> " + nameToApply);
                    continue;
                }

                localVar.setName(nameToApply, SourceType.USER_DEFINED);
                // Belt-and-suspenders: also update via HighFunctionDBUtil to ensure
                // the database variable matches the HighSymbol's exact storage.
                // This provides a second persistence path for register-based variables
                // whose storage may not match across decompilation sessions.
                try {
                    HighFunctionDBUtil.updateDBVariable(
                        symbol, nameToApply, highVar.getDataType(), SourceType.USER_DEFINED);
                } catch (DuplicateNameException ignored) {
                    // Already renamed via localVar.setName above
                } catch (Exception e2) {
                    Msg.debug(this, "Secondary updateDBVariable for " + fromName
                        + ": " + e2.getMessage());
                }
                appliedRenameRequests.add(rename);
                appliedRenameTargetsByOriginal.put(fromName, nameToApply);
                addAppliedRenameRecord(appliedRenameRecordsByOriginal, rename, nameToApply);
                Msg.info(this, "Applied persistent rename for " + fromName + " at " + address
                    + " -> " + nameToApply);
            } catch (DuplicateNameException | InvalidInputException e) {
                Msg.debug(this, "Rename conflict for " + fromName + " -> " + toName + ": " + e.getMessage());
            } catch (Exception e) {
                Msg.warn(this, "Failed to rename variable " + fromName + ": " + e.getMessage(), e);
            }
        }

        // Resolve deferred stack-offset fallback renames now that locals are committed
        // to the database. Stack arrays (e.g. char[64] at stack offset -0x58) become
        // discoverable via function.getLocalVariables() only after the commit above.
        Map<LocalVariable, String> stackFallbackRenames = new HashMap<>();
        for (DeferredStackRename deferred : deferredStackRenames) {
            LocalVariable stackLocal = InferenceNameUtils.findLocalVariableByStackOffset(
                function, deferred.getStackOffset());
            if (stackLocal != null) {
                Msg.info(this, "VariablesMapping stack-offset fallback at " + address
                    + ": original=" + deferred.getOriginalName() + ", target=" + deferred.getNewName()
                    + ", matched LocalVariable=" + stackLocal.getName());
                stackFallbackRenames.put(stackLocal, deferred.getNewName());
            } else {
                Msg.info(this, "VariablesMapping unresolved at " + address
                    + ": original=" + deferred.getOriginalName() + ", target=" + deferred.getNewName());
            }
        }

        // Apply stack-offset fallback renames for variables not in the
        // HighFunction's LocalSymbolMap (e.g. stack char arrays).
        for (Map.Entry<LocalVariable, String> fallback : stackFallbackRenames.entrySet()) {
            LocalVariable stackLocal = fallback.getKey();
            String newName = fallback.getValue();
            try {
                if (InferenceNameUtils.isPlaceholderName(newName)) {
                    continue;
                }
                String nameToApply = InferenceNameUtils.isValidName(newName) ? newName : "_" + newName;
                stackLocal.setName(nameToApply, SourceType.USER_DEFINED);
                Msg.info(this, "Applied stack-offset rename for " + stackLocal.getName()
                    + " at " + address + " -> " + nameToApply);
            } catch (DuplicateNameException | InvalidInputException e) {
                Msg.debug(this, "Stack-offset rename conflict for " + stackLocal.getName()
                    + " -> " + newName + ": " + e.getMessage());
            } catch (Exception e) {
                Msg.warn(this, "Failed stack-offset rename for " + stackLocal.getName()
                    + ": " + e.getMessage(), e);
            }
        }

        // Apply global variable renames (DAT_*, PTR_*, etc.)
        applyGlobalRenames(program, address, globalRenames);

        if (renameRequests.isEmpty() && deferredStackRenames.isEmpty() && globalRenames.isEmpty()) {
            Msg.info(this, "No local variable renames applied for " + address
                + " after evaluating " + variablesMapping.size() + " entries");
        }

        // Defer verification to post-batch: re-decompilation and re-application of
        // register-based renames must happen AFTER all inferences in the batch are applied.
        // Other inferences (parameter_type, return_type for called functions) can change
        // the entry function's decompilation layout, causing firstUseOffset mismatches
        // that only manifest after the full batch is committed.
        if (!appliedRenameRequests.isEmpty()) {
            pendingVerifications.add(new PendingVerification(
                address, function, new ArrayList<>(appliedRenameRequests)));
        }

        // Persist latest mapping so type-change/caller refresh can re-apply renames
        // after later re-decompilations in subsequent inference batches.
        if (!variablesMapping.isEmpty()) {
            inferenceStorage.storeLastVariablesMapping(address, mapping);
        }
        if (!appliedRenameTargetsByOriginal.isEmpty()) {
            inferenceStorage.storeAppliedVariableRenames(address, appliedRenameTargetsByOriginal);
        }
        if (!appliedRenameRecordsByOriginal.isEmpty()) {
            inferenceStorage.storeAppliedVariableRenameRecords(address, appliedRenameRecordsByOriginal);
        }
    }

    /**
     * Run all pending post-batch verifications. Must be called AFTER all inferences
     * in the batch are applied so that the decompiler sees the final state of all
     * function signatures, struct definitions, and type changes.
     */
    public void runPendingVerifications(Program program) {
        if (pendingVerifications.isEmpty()) {
            return;
        }
        List<PendingVerification> batch = new ArrayList<>(pendingVerifications);
        pendingVerifications.clear();

        DecompilerManager decompilerManager = new DecompilerManager();
        for (PendingVerification pv : batch) {
            try {
                verifyAndReapplyRenames(
                    program, pv.getFunction(), pv.getAddress(),
                    pv.getRenameRequests(), decompilerManager);
            } catch (Exception e) {
                Msg.warn(this, "Post-batch verification failed at " + pv.getAddress()
                    + ": " + e.getMessage(), e);
            }
        }
    }

    /**
     * Re-decompile the function and verify that applied renames are visible.
     * For any register-based renames that didn't survive (auto-generated name reappears),
     * re-apply using updateDBVariable on the fresh HighSymbol whose firstUseOffset
     * matches the decompiler's current layout.
     */
    private void verifyAndReapplyRenames(
            Program program,
            Function function,
            Address address,
            List<RenameRequest> renameRequests,
            DecompilerManager decompilerManager) {
        DecompileResults verifyResults = decompilerManager.decompileFunction(
            program, function,
            ZenyardConstants.DECOMPILER_TIMEOUT_SECONDS,
            TaskMonitor.DUMMY
        );
        if (!verifyResults.decompileCompleted()) {
            Msg.debug(this, "Verification decompilation failed at " + address);
            return;
        }
        HighFunction verifyHF = verifyResults.getHighFunction();
        if (verifyHF == null) {
            return;
        }

        // Build name->symbol and storage->symbol maps from the fresh decompilation
        Map<String, HighSymbol> freshNameToSymbol = new HashMap<>();
        Set<String> freshNames = new HashSet<>();
        Map<String, List<HighSymbol>> freshStorageToSymbols = new HashMap<>();
        Map<String, List<HighSymbol>> freshIdentityToSymbols = new HashMap<>();
        LocalSymbolMap freshSymbolMap = verifyHF.getLocalSymbolMap();
        Iterator<HighSymbol> freshIter = freshSymbolMap.getSymbols();
        while (freshIter.hasNext()) {
            HighSymbol sym = freshIter.next();
            HighVariable var = sym.getHighVariable();
            if (var != null && var.getName() != null) {
                freshNames.add(var.getName());
                freshNameToSymbol.put(var.getName(), sym);
                ghidra.program.model.pcode.Varnode rep = var.getRepresentative();
                if (rep != null) {
                    String storageKey = rep.getAddress().toString() + ":" + rep.getSize();
                    freshStorageToSymbols.computeIfAbsent(storageKey, k -> new ArrayList<>()).add(sym);
                    VariableStorageIdentity identity = InferenceNameUtils.toStorageIdentity(rep);
                    if (identity != null) {
                        freshIdentityToSymbols.computeIfAbsent(identity.asKey(), k -> new ArrayList<>()).add(sym);
                    }
                }
            }
        }

        // Check each rename - if the target name is NOT visible, find the corresponding
        // variable in the fresh decompilation and re-apply. Uses two strategies:
        // 1) Match by auto-variable index (e.g. pvVar1 index 1 -> pRVar1 index 1)
        // 2) Fallback: match by storage address from the original HighSymbol
        int reapplied = 0;
        for (RenameRequest rename : renameRequests) {
            String targetName = rename.getTargetName();
            if (InferenceNameUtils.isPlaceholderName(targetName)) {
                continue;
            }
            String nameToApply = InferenceNameUtils.isValidName(targetName) ? targetName : "_" + targetName;
            String originalName = rename.getOriginalName();
            VariableStorageIdentity expectedIdentity = rename.getExpectedIdentity();
            HighSymbol expectedSymbol = findSymbolByIdentity(freshIdentityToSymbols, expectedIdentity);
            if (expectedSymbol != null) {
                if (symbolHasName(expectedSymbol, nameToApply)) {
                    Msg.debug(this, "Verification: target '" + nameToApply + "' already present on expected symbol"
                        + " for '" + originalName + "' at " + address);
                    continue;
                }
                HighSymbol conflictingOwner = freshNameToSymbol.get(nameToApply);
                if (conflictingOwner != null && conflictingOwner != expectedSymbol) {
                    boolean reclaimed = reclaimConflictingTargetName(
                        address,
                        originalName,
                        nameToApply,
                        expectedSymbol,
                        conflictingOwner,
                        freshNameToSymbol,
                        inferenceStorage.getAppliedVariableRenameRecords(address)
                    );
                    if (!reclaimed) {
                        Msg.info(this, "Verification conflict at " + address + ": target '" + nameToApply
                            + "' belongs to different symbol for original '" + originalName + "'");
                        continue;
                    }
                }
                if (applyRenameToHighSymbol(expectedSymbol, nameToApply)) {
                    reapplied++;
                    Msg.info(this, "Verification re-applied rename at " + address
                        + ": " + expectedSymbol.getName() + " -> " + nameToApply
                        + " (original=" + originalName + ", resolution=exact_identity)");
                }
                continue;
            }

            if (freshNames.contains(nameToApply)) {
                Msg.debug(this, "Verification: target '" + nameToApply + "' present but expected identity "
                    + "for '" + originalName + "' is unavailable at " + address);
                continue; // Without identity we cannot safely reclaim ownership
            }

            // Strategy 1: Match by auto-variable index
            HighSymbol freshMatch = null;
            Integer targetIndex = InferenceNameUtils.extractAutoVarIndex(originalName);
            if (targetIndex != null) {
                String originalFamily = extractAutoVarFamily(originalName);
                for (Map.Entry<String, HighSymbol> entry : freshNameToSymbol.entrySet()) {
                    String candidateName = entry.getKey();
                    if (!InferenceNameUtils.isAutoGeneratedVariableName(candidateName)) {
                        continue;
                    }
                    Integer candidateIndex = InferenceNameUtils.extractAutoVarIndex(candidateName);
                    if (candidateIndex != null && targetIndex.equals(candidateIndex)) {
                        if (!isCompatibleAutoVarFamily(
                                originalFamily, extractAutoVarFamily(candidateName))) {
                            continue;
                        }
                        if (!isRenamableSymbol(entry.getValue())) {
                            continue;
                        }
                        freshMatch = entry.getValue();
                        break;
                    }
                }
            }

            // Strategy 2: Fallback - match by storage address from the original symbol
            if (freshMatch == null) {
                freshMatch = findSymbolByIdentity(freshIdentityToSymbols, expectedIdentity);
            }

            if (freshMatch == null) {
                HighSymbol originalSymbol = rename.getSymbol();
                if (originalSymbol != null) {
                    HighVariable originalVar = originalSymbol.getHighVariable();
                    if (originalVar != null) {
                        ghidra.program.model.pcode.Varnode originalRep = originalVar.getRepresentative();
                        if (originalRep != null) {
                            String storageKey = originalRep.getAddress().toString()
                                + ":" + originalRep.getSize();
                            List<HighSymbol> candidates = freshStorageToSymbols.get(storageKey);
                            if (candidates != null) {
                                for (HighSymbol candidate : candidates) {
                                    HighVariable candidateVar = candidate.getHighVariable();
                                    if (candidateVar != null
                                            && InferenceNameUtils.isAutoGeneratedVariableName(
                                                candidateVar.getName())
                                            && isRenamableSymbol(candidate)) {
                                        freshMatch = candidate;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (freshMatch == null) {
                Msg.info(this, "Verification: no matching variable for '" + originalName
                    + "' -> '" + nameToApply + "' at " + address);
                continue;
            }

            try {
                if (applyRenameToHighSymbol(freshMatch, nameToApply)) {
                    reapplied++;
                    Msg.info(this, "Verification re-applied rename at " + address
                        + ": " + freshMatch.getName() + " -> " + nameToApply
                        + " (original=" + originalName + ", resolution=heuristic)");
                }
            } catch (Exception e) {
                Msg.debug(this, "Verification rename failed at " + address
                    + ": " + nameToApply + " - " + e.getMessage());
            }
        }
        if (reapplied > 0) {
            Msg.debug(this, "Verification pass at " + address + ": re-applied " + reapplied + " renames");
        }
    }

    private SymbolResolution resolveSymbol(
        Address functionAddress,
        String originalName,
        String normalizedOriginalName,
        Map<String, HighSymbol> variableNameToSymbol,
        Map<String, List<HighSymbol>> variableNameToSymbols,
        Map<String, VariableStorageIdentity> persistedIdentities,
        Map<String, List<HighSymbol>> identityKeyToSymbols
    ) {
        VariableStorageIdentity persistedIdentity = persistedIdentities.get(originalName);
        if (persistedIdentity == null && normalizedOriginalName != null
            && !normalizedOriginalName.equals(originalName)) {
            persistedIdentity = persistedIdentities.get(normalizedOriginalName);
        }

        String scopedOriginalName = scopedLookupKey(functionAddress, originalName);
        List<HighSymbol> exactMatches = variableNameToSymbols.getOrDefault(
            scopedOriginalName, Collections.emptyList());
        if (exactMatches.size() == 1) {
            return new SymbolResolution(exactMatches.get(0), "exact_name");
        }
        if (exactMatches.size() > 1) {
            HighSymbol byIdentity = resolveCandidateByPersistedIdentity(exactMatches, persistedIdentity);
            if (byIdentity != null) {
                return new SymbolResolution(byIdentity, "exact_name_persisted_identity");
            }
            HighSymbol singleRenamable = resolveSingleRenamableCandidate(exactMatches);
            if (singleRenamable != null) {
                return new SymbolResolution(singleRenamable, "exact_name_single_renamable");
            }
            return new SymbolResolution(null, "ambiguous_exact_name");
        }

        HighSymbol byName = variableNameToSymbol.get(scopedOriginalName);
        if (byName != null) {
            return new SymbolResolution(byName, "exact_name");
        }
        if (normalizedOriginalName != null && !normalizedOriginalName.equals(originalName)) {
            String scopedNormalizedName = scopedLookupKey(functionAddress, normalizedOriginalName);
            List<HighSymbol> normalizedMatches = variableNameToSymbols.getOrDefault(
                scopedNormalizedName, Collections.emptyList());
            if (normalizedMatches.size() == 1) {
                return new SymbolResolution(normalizedMatches.get(0), "normalized_name");
            }
            if (normalizedMatches.size() > 1) {
                HighSymbol byIdentity = resolveCandidateByPersistedIdentity(
                    normalizedMatches, persistedIdentity);
                if (byIdentity != null) {
                    return new SymbolResolution(byIdentity, "normalized_name_persisted_identity");
                }
                HighSymbol singleRenamable = resolveSingleRenamableCandidate(normalizedMatches);
                if (singleRenamable != null) {
                    return new SymbolResolution(singleRenamable, "normalized_name_single_renamable");
                }
                return new SymbolResolution(null, "ambiguous_normalized_name");
            }

            byName = variableNameToSymbol.get(scopedNormalizedName);
            if (byName != null) {
                return new SymbolResolution(byName, "normalized_name");
            }
        }

        if (persistedIdentity != null) {
            List<HighSymbol> identityMatches = identityKeyToSymbols.getOrDefault(
                persistedIdentity.asKey(),
                Collections.emptyList()
            );
            if (identityMatches.size() == 1) {
                return new SymbolResolution(identityMatches.get(0), "persisted_identity");
            }
        }
        HighSymbol byAutoPattern = resolveAutoGeneratedSymbol(
            variableNameToSymbol,
            normalizedOriginalName != null ? normalizedOriginalName : originalName,
            persistedIdentity != null ? persistedIdentity.getKind() : null
        );
        if (byAutoPattern != null) {
            return new SymbolResolution(byAutoPattern, "auto_generated_fallback");
        }

        return new SymbolResolution(null, "unresolved");
    }

    private HighSymbol resolveAutoGeneratedSymbol(
        Map<String, HighSymbol> variableNameToSymbol,
        String originalName,
        String preferredStorageKind
    ) {
        Integer targetIndex = InferenceNameUtils.extractAutoVarIndex(originalName);
        if (targetIndex == null) {
            return null;
        }
        Set<HighSymbol> candidates = new LinkedHashSet<>();
        String originalFamily = extractAutoVarFamily(originalName);
        for (Map.Entry<String, HighSymbol> entry : variableNameToSymbol.entrySet()) {
            String candidateName = unscopedLookupName(entry.getKey());
            Integer candidateIndex = InferenceNameUtils.extractAutoVarIndex(candidateName);
            if (candidateIndex != null
                && targetIndex.equals(candidateIndex)
                && InferenceNameUtils.isAutoGeneratedVariableName(candidateName)) {
                if (!isCompatibleAutoVarFamily(originalFamily, extractAutoVarFamily(candidateName))) {
                    continue;
                }
                if (preferredStorageKind != null) {
                    HighVariable candidateVar = entry.getValue().getHighVariable();
                    if (candidateVar == null) {
                        continue;
                    }
                    VariableStorageIdentity candidateIdentity =
                        InferenceNameUtils.toStorageIdentity(candidateVar.getRepresentative());
                    if (candidateIdentity == null || !preferredStorageKind.equals(candidateIdentity.getKind())) {
                        continue;
                    }
                }
                if (!isRenamableSymbol(entry.getValue())) {
                    continue;
                }
                candidates.add(entry.getValue());
            }
        }
        return candidates.size() == 1 ? candidates.iterator().next() : null;
    }

    private static String scopedLookupKey(Address functionAddress, String localVariableName) {
        if (functionAddress == null || localVariableName == null || localVariableName.isEmpty()) {
            return localVariableName;
        }
        return functionAddress + "_" + localVariableName;
    }

    private static String unscopedLookupName(String scopedLookupKey) {
        if (scopedLookupKey == null) {
            return null;
        }
        int separator = scopedLookupKey.indexOf('_');
        if (separator < 0 || separator + 1 >= scopedLookupKey.length()) {
            return scopedLookupKey;
        }
        return scopedLookupKey.substring(separator + 1);
    }

    private static void addUniqueSymbol(Map<String, List<HighSymbol>> symbolMap, String key,
            HighSymbol symbol) {
        List<HighSymbol> symbols = symbolMap.computeIfAbsent(key, ignored -> new ArrayList<>());
        if (!symbols.contains(symbol)) {
            symbols.add(symbol);
        }
    }

    private static HighSymbol resolveSingleRenamableCandidate(List<HighSymbol> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return null;
        }
        HighSymbol match = null;
        for (HighSymbol candidate : candidates) {
            if (!isRenamableSymbol(candidate)) {
                continue;
            }
            if (match != null) {
                return null;
            }
            match = candidate;
        }
        return match;
    }

    private static boolean isRenamableSymbol(HighSymbol symbol) {
        if (symbol == null) {
            return false;
        }
        HighVariable variable = symbol.getHighVariable();
        if (variable == null) {
            return false;
        }
        ghidra.program.model.pcode.Varnode representative = variable.getRepresentative();
        if (representative == null || representative.getAddress() == null) {
            return false;
        }
        Address storageAddress = representative.getAddress();
        return storageAddress.isUniqueAddress()
            || storageAddress.isStackAddress()
            || storageAddress.isRegisterAddress();
    }

    private static String extractAutoVarFamily(String name) {
        if (name == null) {
            return null;
        }
        String normalized = name;
        while (normalized.startsWith("_")) {
            normalized = normalized.substring(1);
        }
        String lower = normalized.toLowerCase();
        java.util.regex.Matcher matcher = java.util.regex.Pattern
            .compile("^([a-z]+)var\\d+$")
            .matcher(lower);
        if (!matcher.matches()) {
            return null;
        }
        return matcher.group(1);
    }

    private static boolean isCompatibleAutoVarFamily(String expectedFamily, String candidateFamily) {
        if (expectedFamily == null || candidateFamily == null) {
            return true;
        }
        if (expectedFamily.equals(candidateFamily)) {
            return true;
        }
        boolean expectedPointerLike = expectedFamily.startsWith("p");
        boolean candidatePointerLike = candidateFamily.startsWith("p");
        if (expectedPointerLike != candidatePointerLike) {
            return false;
        }
        // Allow family drift inside the same broad storage/type class after re-decompilation.
        return true;
    }

    private HighSymbol resolveCandidateByPersistedIdentity(
        List<HighSymbol> candidates,
        VariableStorageIdentity persistedIdentity
    ) {
        if (persistedIdentity == null || candidates == null || candidates.isEmpty()) {
            return null;
        }
        HighSymbol match = null;
        for (HighSymbol candidate : candidates) {
            if (candidate == null) {
                continue;
            }
            HighVariable candidateVar = candidate.getHighVariable();
            if (candidateVar == null) {
                continue;
            }
            VariableStorageIdentity candidateIdentity =
                InferenceNameUtils.toStorageIdentity(candidateVar.getRepresentative());
            if (candidateIdentity == null) {
                continue;
            }
            if (!persistedIdentity.asKey().equals(candidateIdentity.asKey())) {
                continue;
            }
            if (match != null) {
                return null;
            }
            match = candidate;
        }
        return match;
    }

    private boolean renameSymbolInDatabase(HighSymbol symbol, String nameToApply) {
        try {
            HighVariable highVar = symbol.getHighVariable();
            DataType currentType = highVar != null ? highVar.getDataType() : null;
            if (currentType == null) {
                return false;
            }
            HighFunctionDBUtil.updateDBVariable(
                symbol,
                nameToApply,
                currentType,
                SourceType.USER_DEFINED
            );
            return true;
        } catch (Exception e) {
            Msg.debug(this, "Symbol fallback rename failed for " + symbol.getName() + ": " + e.getMessage());
            return false;
        }
    }

    private static class DeferredStackRename {
        private final long stackOffset;
        private final String originalName;
        private final String newName;

        DeferredStackRename(long stackOffset, String originalName, String newName) {
            this.stackOffset = stackOffset;
            this.originalName = originalName;
            this.newName = newName;
        }

        long getStackOffset() {
            return stackOffset;
        }

        String getOriginalName() {
            return originalName;
        }

        String getNewName() {
            return newName;
        }
    }

    private static class RenameRequest {
        private final String originalName;
        private final String targetName;
        private final HighSymbol symbol;
        private final VariableStorageIdentity expectedIdentity;

        private RenameRequest(
            String originalName,
            String targetName,
            HighSymbol symbol,
            VariableStorageIdentity expectedIdentity
        ) {
            this.originalName = originalName;
            this.targetName = targetName;
            this.symbol = symbol;
            this.expectedIdentity = expectedIdentity;
        }

        private String getOriginalName() {
            return originalName;
        }

        private String getTargetName() {
            return targetName;
        }

        private HighSymbol getSymbol() {
            return symbol;
        }

        private VariableStorageIdentity getExpectedIdentity() {
            return expectedIdentity;
        }
    }

    private static class SymbolResolution {
        private final HighSymbol symbol;
        private final String mode;

        private SymbolResolution(HighSymbol symbol, String mode) {
            this.symbol = symbol;
            this.mode = mode;
        }

        private HighSymbol getSymbol() {
            return symbol;
        }

        private String getMode() {
            return mode;
        }
    }

    private static class PendingVerification {
        private final Address address;
        private final Function function;
        private final List<RenameRequest> renameRequests;

        PendingVerification(Address address, Function function, List<RenameRequest> renameRequests) {
            this.address = address;
            this.function = function;
            this.renameRequests = renameRequests;
        }

        Address getAddress() {
            return address;
        }

        Function getFunction() {
            return function;
        }

        List<RenameRequest> getRenameRequests() {
            return renameRequests;
        }
    }

    private static class GlobalRenameRequest {
        private final String originalName;
        private final String newName;

        GlobalRenameRequest(String originalName, String newName) {
            this.originalName = originalName;
            this.newName = newName;
        }

        String getOriginalName() {
            return originalName;
        }

        String getNewName() {
            return newName;
        }
    }

    /**
     * Check if a variable name is a global data label auto-generated by Ghidra.
     * Matches patterns like DAT_XXXXXXXX, _DAT_XXXXXXXX, PTR_XXXXXXXX, s_XXXXXXXX.
     */
    private static boolean isGlobalDataLabel(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        String normalized = name;
        while (normalized.startsWith("_")) {
            normalized = normalized.substring(1);
        }
        return normalized.matches("^DAT_[0-9a-fA-F]+$")
            || normalized.matches("^PTR_[0-9a-fA-F]+$")
            || normalized.matches("^s_[0-9a-fA-F]+$");
    }

    /**
     * Extract a Ghidra address from a global data label name like "DAT_10000812c".
     * Returns null if the name doesn't match the expected pattern.
     */
    private static Address parseGlobalLabelAddress(Program program, String name) {
        if (name == null) {
            return null;
        }
        String normalized = name;
        while (normalized.startsWith("_")) {
            normalized = normalized.substring(1);
        }
        int underscoreIdx = normalized.indexOf('_');
        if (underscoreIdx < 0 || underscoreIdx + 1 >= normalized.length()) {
            return null;
        }
        String hexPart = normalized.substring(underscoreIdx + 1);
        try {
            AddressFactory factory = program.getAddressFactory();
            return factory.getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(hexPart, 16));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Apply renames for global data labels (DAT_*, PTR_*, etc.) via the SymbolTable.
     */
    private void applyGlobalRenames(Program program, Address functionAddress,
            List<GlobalRenameRequest> globalRenames) {
        if (globalRenames.isEmpty()) {
            return;
        }
        SymbolTable symbolTable = program.getSymbolTable();
        for (GlobalRenameRequest request : globalRenames) {
            String originalName = request.getOriginalName();
            String newName = request.getNewName();
            try {
                if (InferenceNameUtils.isPlaceholderName(newName)) {
                    continue;
                }
                String nameToApply = InferenceNameUtils.isValidName(newName) ? newName : "_" + newName;
                Address globalAddr = parseGlobalLabelAddress(program, originalName);
                if (globalAddr == null) {
                    Msg.info(this, "Cannot parse global address from '" + originalName
                        + "' at function " + functionAddress);
                    continue;
                }
                Symbol sym = symbolTable.getPrimarySymbol(globalAddr);
                if (sym == null) {
                    // Try finding by name in the global namespace
                    List<Symbol> symbols = symbolTable.getSymbols(originalName, null);
                    if (symbols != null && !symbols.isEmpty()) {
                        sym = symbols.get(0);
                    }
                }
                if (sym == null) {
                    Msg.info(this, "No symbol found for global '" + originalName
                        + "' at " + globalAddr + " (function " + functionAddress + ")");
                    continue;
                }
                if (sym.getSource() == SourceType.USER_DEFINED
                        && !InferenceNameUtils.isAutoGeneratedVariableName(sym.getName())) {
                    Msg.info(this, "Skipping global rename for '" + originalName
                        + "': symbol already has user-defined name '" + sym.getName() + "'");
                    continue;
                }
                sym.setName(nameToApply, SourceType.USER_DEFINED);
                inferenceStorage.putGlobalDatPendingRename(globalAddr, originalName, nameToApply, functionAddress);
                reconcilePendingIfStructuredGlobalAlreadyCovers(program, globalAddr);
                Msg.info(this, "Applied global rename at " + globalAddr
                    + ": " + originalName + " -> " + nameToApply);
            } catch (DuplicateNameException e) {
                Msg.debug(this, "Global rename conflict for " + originalName
                    + " -> " + newName + ": " + e.getMessage());
            } catch (InvalidInputException e) {
                Msg.debug(this, "Global rename invalid input for " + originalName
                    + " -> " + newName + ": " + e.getMessage());
            } catch (Exception e) {
                Msg.warn(this, "Failed global rename for " + originalName
                    + " -> " + newName + ": " + e.getMessage(), e);
            }
        }
    }

    /**
     * After {@code global_variable_type} creates or confirms structured data at {@code structuredBaseAddress},
     * applies pending DAT_* semantic names (from variables_mapping) as EOL comments on the covered
     * addresses and clears the pending registry for those entries.
     */
    public void reconcilePendingGlobalDatRenamesForStructuredBase(Program program, Address structuredBaseAddress) {
        if (program == null || program.isClosed() || structuredBaseAddress == null) {
            return;
        }
        Listing listing = program.getListing();
        Data data = listing.getDataAt(structuredBaseAddress);
        if (data == null) {
            data = listing.getDataContaining(structuredBaseAddress);
        }
        if (data == null) {
            return;
        }
        Address min = data.getMinAddress();
        Address max = data.getMaxAddress();
        Map<String, GlobalDatPendingRenameEntry> pending = inferenceStorage.getGlobalDatPendingRenames();
        if (pending.isEmpty()) {
            return;
        }
        for (GlobalDatPendingRenameEntry entry : new ArrayList<>(pending.values())) {
            if (entry == null || entry.getMemoryAddressKey() == null) {
                continue;
            }
            Address memAddr = AddressHelper.fromApiAddressKey(program, entry.getMemoryAddressKey());
            if (memAddr == null) {
                continue;
            }
            if (memAddr.compareTo(min) < 0 || memAddr.compareTo(max) > 0) {
                continue;
            }
            String label = entry.getNewName();
            if (label == null || label.isBlank()) {
                inferenceStorage.removeGlobalDatPendingRename(memAddr);
                continue;
            }
            try {
                listing.setComment(memAddr, CommentType.EOL, label);
            } catch (Exception e) {
                Msg.warn(this, "Failed to set reconciled comment at " + memAddr + ": " + e.getMessage());
            }
            inferenceStorage.removeGlobalDatPendingRename(memAddr);
            Msg.info(this, "Reconciled pending global DAT name with structured global at " + structuredBaseAddress
                + ": " + memAddr + " -> " + label);
        }
    }

    private void reconcilePendingIfStructuredGlobalAlreadyCovers(Program program, Address globalAddr) {
        if (program == null || globalAddr == null) {
            return;
        }
        Data containing = program.getListing().getDataContaining(globalAddr);
        if (containing == null) {
            return;
        }
        Address base = containing.getMinAddress();
        if (inferenceStorage.wasGlobalVariableTypeInferred(base)) {
            reconcilePendingGlobalDatRenamesForStructuredBase(program, base);
        }
    }

    /**
     * Caller-targeted rename refresh. For each type-changed address, finds the calling
     * functions that have a stored variables mapping and re-applies their stored renames.
     * This handles the case where a callee's signature change (return_type, parameter_type)
     * causes Ghidra to re-decompile the caller, which can shift firstUseOffset values and
     * revert register-based variable renames from a previous inference batch.
     *
     * Complexity is O(typeChangedAddresses * avg_callers_per_function), bounded by the
     * call graph density rather than total function count.
     */
    public void refreshCallerRenames(Program program, Set<Address> typeChangedAddresses) {
        refreshCallerRenames(program, typeChangedAddresses, TaskMonitor.DUMMY, () -> false);
    }

    public void refreshCallerRenames(
        Program program,
        Set<Address> typeChangedAddresses,
        TaskMonitor monitor,
        java.util.function.BooleanSupplier shouldStop
    ) {
        if (typeChangedAddresses.isEmpty()) {
            return;
        }
        if (program == null || program.isClosed()) {
            return;
        }
        FunctionManager funcManager = program.getFunctionManager();
        Set<Address> addressesToRefresh = new HashSet<>();

        for (Address changedAddr : typeChangedAddresses) {
            if (shouldStop != null && shouldStop.getAsBoolean()) {
                break;
            }
            if (monitor != null && monitor.isCancelled()) {
                break;
            }
            if (program.isClosed()) {
                break;
            }
            // The function at the changed address itself needs refresh: changing its
            // own return_type or parameter_type triggers re-decompilation, which can
            // revert register-based local variable renames from a previous batch.
            if (inferenceStorage.hasStoredVariablesMapping(changedAddr)
                    || inferenceStorage.hasAppliedVariableRenames(changedAddr)) {
                addressesToRefresh.add(changedAddr);
            }

            Function changedFunc = funcManager.getFunctionAt(changedAddr);
            if (changedFunc == null) {
                continue;
            }
            // Callers of the changed function also need refresh: the callee's new
            // signature can alter the caller's decompilation layout.
            Set<Function> callers = changedFunc.getCallingFunctions(monitor != null ? monitor : TaskMonitor.DUMMY);
            for (Function caller : callers) {
                Address callerAddr = caller.getEntryPoint();
                if (inferenceStorage.hasStoredVariablesMapping(callerAddr)
                        || inferenceStorage.hasAppliedVariableRenames(callerAddr)) {
                    addressesToRefresh.add(callerAddr);
                }
            }
        }

        if (addressesToRefresh.isEmpty()) {
            return;
        }

        Msg.info(this, "Type-change rename refresh: " + addressesToRefresh.size()
            + " functions affected by " + typeChangedAddresses.size() + " type changes");

        DecompilerManager decompilerManager = new DecompilerManager();
        int totalRefreshed = 0;
        for (Address addr : addressesToRefresh) {
            if (shouldStop != null && shouldStop.getAsBoolean()) {
                break;
            }
            if (monitor != null && monitor.isCancelled()) {
                break;
            }
            if (program.isClosed()) {
                break;
            }
            totalRefreshed += refreshStoredRenames(program, addr, decompilerManager, monitor);
        }

        if (totalRefreshed > 0) {
            Msg.info(this, "Type-change rename refresh complete: re-applied "
                + totalRefreshed + " renames across " + addressesToRefresh.size() + " functions");
        }
    }

    /**
     * Refresh variable renames for a single function using its stored mapping.
     * Decompiles fresh and re-applies any renames from storage that reverted to
     * auto-generated names (e.g. due to callee signature changes).
     *
     * @return the number of renames re-applied
     */
    private int refreshStoredRenames(Program program, Address address,
            DecompilerManager decompilerManager, TaskMonitor monitor) {
        Map<String, String> storedAppliedRenames = inferenceStorage.getAppliedVariableRenames(address);
        Map<String, AppliedVariableRenameRecord> storedAppliedRenameRecords =
            inferenceStorage.getAppliedVariableRenameRecords(address);
        VariablesMapping mapping = inferenceStorage.getLastVariablesMapping(address);
        Map<String, String> legacyStoredMapping =
            (mapping != null) ? mapping.getVariablesMapping() : null;
        boolean hasAppliedRenameHistory = storedAppliedRenames != null && !storedAppliedRenames.isEmpty();
        boolean hasLegacyMapping = legacyStoredMapping != null && !legacyStoredMapping.isEmpty();
        if (!hasAppliedRenameHistory && !hasLegacyMapping) {
            return 0;
        }

        Function targetFunction = program.getFunctionManager().getFunctionAt(address);
        if (targetFunction == null) {
            return 0;
        }

        if (program == null || program.isClosed() || (monitor != null && monitor.isCancelled())) {
            return 0;
        }

        DecompileResults results;
        try {
            results = decompilerManager.decompileFunction(
                program,
                targetFunction,
                ZenyardConstants.DECOMPILER_TIMEOUT_SECONDS,
                monitor != null ? monitor : TaskMonitor.DUMMY
            );
        } catch (Exception e) {
            // Program closing can produce ClosedException/DomainObjectException from the decompiler.
            // Treat as an abort and do not propagate (we don't want to take down the batch tx).
            Msg.debug(this, "Skipping rename refresh decompile for " + address + ": " + e.getMessage());
            return 0;
        }
        if (!results.decompileCompleted() || results.getHighFunction() == null) {
            return 0;
        }

        HighFunction hf = results.getHighFunction();
        LocalSymbolMap symMap = hf.getLocalSymbolMap();

        // Build maps from the fresh decompilation
        Map<String, HighSymbol> freshNameToSymbol = new HashMap<>();
        Set<String> freshNames = new HashSet<>();
        Map<String, List<HighSymbol>> freshIdentityToSymbols = new HashMap<>();
        Iterator<HighSymbol> iter = symMap.getSymbols();
        while (iter.hasNext()) {
            HighSymbol sym = iter.next();
            HighVariable var = sym.getHighVariable();
            if (var != null && var.getName() != null) {
                freshNames.add(var.getName());
                freshNameToSymbol.put(var.getName(), sym);
                VariableStorageIdentity identity =
                    InferenceNameUtils.toStorageIdentity(var.getRepresentative());
                if (identity != null) {
                    freshIdentityToSymbols.computeIfAbsent(
                        identity.asKey(), k -> new ArrayList<>()).add(sym);
                }
            }
        }

        // Load persisted storage identities for this function
        Map<String, VariableStorageIdentity> persistedIdentities =
            inferenceStorage.getVariableIdentities(address);

        Map<String, String> storedMapping = new HashMap<>();
        if (hasLegacyMapping) {
            storedMapping.putAll(legacyStoredMapping);
        }
        if (hasAppliedRenameHistory) {
            // Applied history is authoritative; keep as final override.
            storedMapping.putAll(storedAppliedRenames);
        }
        int refreshed = 0;

        for (Map.Entry<String, String> entry : storedMapping.entrySet()) {
            String originalName = entry.getKey();
            String targetName = entry.getValue();

            if (InferenceNameUtils.isPlaceholderName(targetName)) {
                continue;
            }
            String nameToApply = InferenceNameUtils.isValidName(targetName)
                ? targetName : "_" + targetName;
            AppliedVariableRenameRecord storedRecord = storedAppliedRenameRecords.get(originalName);
            VariableStorageIdentity expectedIdentity = storedRecord != null
                ? storedRecord.getStorageIdentity()
                : resolvePersistedIdentity(originalName, persistedIdentities);
            HighSymbol expectedSymbol = findSymbolByIdentity(freshIdentityToSymbols, expectedIdentity);
            if (expectedSymbol != null) {
                if (symbolHasName(expectedSymbol, nameToApply)) {
                    Msg.debug(this, "Caller refresh: target '" + nameToApply + "' already present on expected symbol"
                        + " for '" + originalName + "' at " + address);
                    continue;
                }
                HighSymbol conflictingOwner = freshNameToSymbol.get(nameToApply);
                if (conflictingOwner != null && conflictingOwner != expectedSymbol) {
                    boolean reclaimed = reclaimConflictingTargetName(
                        address,
                        originalName,
                        nameToApply,
                        expectedSymbol,
                        conflictingOwner,
                        freshNameToSymbol,
                        storedAppliedRenameRecords
                    );
                    if (!reclaimed) {
                        Msg.info(this, "Caller refresh conflict at " + address + ": target '" + nameToApply
                            + "' belongs to different symbol for original '" + originalName + "'");
                        continue;
                    }
                }
                if (applyRenameToHighSymbol(expectedSymbol, nameToApply)) {
                    refreshed++;
                    Msg.info(this, "Caller refresh re-applied at " + address
                        + ": " + expectedSymbol.getName() + " -> " + nameToApply
                        + " (stored original=" + originalName + ", resolution=exact_identity)");
                }
                continue;
            }

            if (freshNames.contains(nameToApply)) {
                Msg.debug(this, "Caller refresh: target '" + nameToApply + "' present but expected identity "
                    + "for '" + originalName + "' is unavailable at " + address);
                continue;
            }

            // Find a matching auto-generated variable in the fresh decompilation
            HighSymbol match = findAutoGenMatchForRefresh(
                originalName,
                freshNameToSymbol,
                freshIdentityToSymbols,
                persistedIdentities,
                expectedIdentity
            );
            if (match == null) {
                continue;
            }

            try {
                if (applyRenameToHighSymbol(match, nameToApply)) {
                    refreshed++;
                    Msg.info(this, "Caller refresh re-applied at " + address
                        + ": " + match.getName() + " -> " + nameToApply
                        + " (stored original=" + originalName + ", resolution=heuristic)");
                }
            } catch (Exception e) {
                Msg.debug(this, "Caller refresh rename failed at " + address
                    + ": " + nameToApply + " - " + e.getMessage());
            }
        }
        if (refreshed > 0) {
            Msg.debug(this, "Caller refresh pass at " + address + ": re-applied " + refreshed + " renames");
        }
        return refreshed;
    }

    /**
     * Find a matching auto-generated HighSymbol for a stored mapping entry by:
     * 1) Exact original name still present as auto-generated
     * 2) Auto-variable index match (e.g. iVar1 index 1 -> pRVar1 index 1)
     * 3) Storage identity match from persisted identities
     */
    private HighSymbol findAutoGenMatchForRefresh(
            String originalName,
            Map<String, HighSymbol> freshNameToSymbol,
            Map<String, List<HighSymbol>> freshIdentityToSymbols,
            Map<String, VariableStorageIdentity> persistedIdentities,
            VariableStorageIdentity preferredIdentity) {

        // Strategy 1: exact original name reappeared as auto-generated
        HighSymbol byName = freshNameToSymbol.get(originalName);
        if (byName != null) {
            HighVariable var = byName.getHighVariable();
            if (var != null
                    && InferenceNameUtils.isAutoGeneratedVariableName(var.getName())
                    && isRenamableSymbol(byName)) {
                return byName;
            }
        }

        // Strategy 2: exact persisted storage identity
        HighSymbol byIdentity = findSymbolByIdentity(freshIdentityToSymbols, preferredIdentity);
        if (byIdentity != null && isRenamableSymbol(byIdentity)) {
            return byIdentity;
        }

        // Strategy 3: match by auto-variable index
        Integer targetIndex = InferenceNameUtils.extractAutoVarIndex(originalName);
        if (targetIndex != null) {
            String preferredKind = null;
            String originalFamily = extractAutoVarFamily(originalName);
            VariableStorageIdentity identity = preferredIdentity != null
                ? preferredIdentity
                : resolvePersistedIdentity(originalName, persistedIdentities);
            if (identity != null) {
                preferredKind = identity.getKind();
            }

            Set<HighSymbol> candidates = new LinkedHashSet<>();
            for (Map.Entry<String, HighSymbol> e : freshNameToSymbol.entrySet()) {
                String candidateName = e.getKey();
                if (!InferenceNameUtils.isAutoGeneratedVariableName(candidateName)) {
                    continue;
                }
                Integer candidateIndex = InferenceNameUtils.extractAutoVarIndex(candidateName);
                if (candidateIndex != null && targetIndex.equals(candidateIndex)) {
                    if (!isCompatibleAutoVarFamily(
                            originalFamily, extractAutoVarFamily(candidateName))) {
                        continue;
                    }
                    if (preferredKind != null) {
                        HighVariable candidateVar = e.getValue().getHighVariable();
                        if (candidateVar == null) {
                            continue;
                        }
                        VariableStorageIdentity candidateIdentity =
                            InferenceNameUtils.toStorageIdentity(candidateVar.getRepresentative());
                        if (candidateIdentity == null
                                || !preferredKind.equals(candidateIdentity.getKind())) {
                            continue;
                        }
                    }
                    if (!isRenamableSymbol(e.getValue())) {
                        continue;
                    }
                    candidates.add(e.getValue());
                }
            }
            if (candidates.size() == 1) {
                return candidates.iterator().next();
            }
        }

        // Strategy 4: persisted storage identity as a final exact fallback
        VariableStorageIdentity identity = preferredIdentity != null
            ? preferredIdentity
            : resolvePersistedIdentity(originalName, persistedIdentities);
        if (identity != null) {
            List<HighSymbol> candidates = freshIdentityToSymbols.getOrDefault(
                identity.asKey(), Collections.emptyList());
            for (HighSymbol sym : candidates) {
                HighVariable var = sym.getHighVariable();
                if (var != null
                        && InferenceNameUtils.isAutoGeneratedVariableName(var.getName())
                        && isRenamableSymbol(sym)) {
                    return sym;
                }
            }
        }

        return null;
    }

    static VariableStorageIdentity resolvePersistedIdentity(
        String originalName,
        Map<String, VariableStorageIdentity> persistedIdentities
    ) {
        if (persistedIdentities == null || originalName == null) {
            return null;
        }
        VariableStorageIdentity identity = persistedIdentities.get(originalName);
        if (identity != null) {
            return identity;
        }
        String normalized = InferenceNameUtils.normalizeVariableLookupName(originalName);
        if (normalized != null && !normalized.equals(originalName)) {
            return persistedIdentities.get(normalized);
        }
        return null;
    }

    private static HighSymbol findSymbolByIdentity(
        Map<String, List<HighSymbol>> symbolsByIdentity,
        VariableStorageIdentity identity
    ) {
        if (symbolsByIdentity == null || identity == null) {
            return null;
        }
        List<HighSymbol> candidates = symbolsByIdentity.getOrDefault(
            identity.asKey(),
            Collections.emptyList()
        );
        return candidates.size() == 1 ? candidates.get(0) : null;
    }

    private static boolean symbolHasName(HighSymbol symbol, String expectedName) {
        if (symbol == null || expectedName == null) {
            return false;
        }
        HighVariable variable = symbol.getHighVariable();
        return variable != null && expectedName.equals(variable.getName());
    }

    static String findAlternateRenameTarget(
        VariableStorageIdentity ownerIdentity,
        String conflictingTarget,
        Map<String, AppliedVariableRenameRecord> storedRenameRecords
    ) {
        if (ownerIdentity == null || conflictingTarget == null || storedRenameRecords == null) {
            return null;
        }
        for (AppliedVariableRenameRecord record : storedRenameRecords.values()) {
            if (record == null || record.getStorageIdentity() == null) {
                continue;
            }
            if (!ownerIdentity.asKey().equals(record.getStorageIdentity().asKey())) {
                continue;
            }
            String alternateTarget = record.getTargetName();
            if (alternateTarget != null && !alternateTarget.isBlank()
                && !conflictingTarget.equals(alternateTarget)) {
                return alternateTarget;
            }
        }
        return null;
    }

    static boolean shouldReclaimConflictingTarget(
        VariableStorageIdentity expectedIdentity,
        VariableStorageIdentity conflictingIdentity,
        String alternateTargetForConflictingOwner
    ) {
        if (expectedIdentity == null || conflictingIdentity == null) {
            return false;
        }
        if (expectedIdentity.asKey().equals(conflictingIdentity.asKey())) {
            return false;
        }
        return alternateTargetForConflictingOwner != null
            && !alternateTargetForConflictingOwner.isBlank();
    }

    private boolean reclaimConflictingTargetName(
        Address functionAddress,
        String originalName,
        String targetName,
        HighSymbol expectedSymbol,
        HighSymbol conflictingOwner,
        Map<String, HighSymbol> freshNameToSymbol,
        Map<String, AppliedVariableRenameRecord> storedRenameRecords
    ) {
        VariableStorageIdentity expectedIdentity = InferenceNameUtils.toStorageIdentity(
            expectedSymbol != null && expectedSymbol.getHighVariable() != null
                ? expectedSymbol.getHighVariable().getRepresentative()
                : null
        );
        VariableStorageIdentity conflictingIdentity = InferenceNameUtils.toStorageIdentity(
            conflictingOwner != null && conflictingOwner.getHighVariable() != null
                ? conflictingOwner.getHighVariable().getRepresentative()
                : null
        );
        String alternateTarget = findAlternateRenameTarget(
            conflictingIdentity,
            targetName,
            storedRenameRecords
        );
        if (!shouldReclaimConflictingTarget(
            expectedIdentity,
            conflictingIdentity,
            alternateTarget
        )) {
            Msg.info(this, "Rename conflict at " + functionAddress + ": target '" + targetName
                + "' owned by wrong symbol for original '" + originalName
                + "' and cannot be safely reclaimed");
            return false;
        }
        if (!applyRenameToHighSymbol(conflictingOwner, alternateTarget)) {
            Msg.info(this, "Rename conflict at " + functionAddress + ": failed to restore conflicting owner"
                + " from '" + targetName + "' to '" + alternateTarget + "' for original '" + originalName + "'");
            return false;
        }
        freshNameToSymbol.remove(targetName);
        freshNameToSymbol.put(alternateTarget, conflictingOwner);
        Msg.info(this, "Reclaimed target '" + targetName + "' at " + functionAddress
            + " by restoring conflicting owner to '" + alternateTarget
            + "' for original '" + originalName + "'");
        return true;
    }

    private boolean applyRenameToHighSymbol(HighSymbol symbol, String nameToApply) {
        if (symbol == null || nameToApply == null || nameToApply.isBlank()) {
            return false;
        }
        HighVariable highVariable = symbol.getHighVariable();
        if (highVariable == null || highVariable.getDataType() == null) {
            return false;
        }
        try {
            HighFunctionDBUtil.updateDBVariable(
                symbol,
                nameToApply,
                highVariable.getDataType(),
                SourceType.USER_DEFINED
            );
            return true;
        } catch (DuplicateNameException e) {
            Msg.debug(this, "Rename conflict for target '" + nameToApply + "': " + e.getMessage());
            return false;
        } catch (Exception e) {
            Msg.debug(this, "Rename apply failed for target '" + nameToApply + "': " + e.getMessage());
            return false;
        }
    }

    private void addAppliedRenameRecord(
        Map<String, AppliedVariableRenameRecord> appliedRenameRecordsByOriginal,
        RenameRequest rename,
        String targetName
    ) {
        if (appliedRenameRecordsByOriginal == null || rename == null
            || targetName == null || targetName.isBlank()) {
            return;
        }
        VariableStorageIdentity expectedIdentity = rename.getExpectedIdentity();
        if (expectedIdentity == null) {
            return;
        }
        appliedRenameRecordsByOriginal.put(
            rename.getOriginalName(),
            new AppliedVariableRenameRecord(targetName, expectedIdentity)
        );
    }
}
