package com.zenyard.ghidra.illum;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.zenyard.ghidra.api.generated.model.FieldDefinition;
import com.zenyard.ghidra.api.generated.model.Inference;
import com.zenyard.ghidra.api.generated.model.ParameterType;
import com.zenyard.ghidra.api.generated.model.ReturnType;
import com.zenyard.ghidra.api.generated.model.StructDefinition;
import com.zenyard.ghidra.storage.InferenceStorage;
import com.zenyard.ghidra.util.TransactionUtils;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Removes inferred structs that have been superseded by backend merging
 * and are no longer referenced anywhere in the program.
 *
 * A struct is eligible for deletion only when:
 * <ol>
 *   <li>Its UUID appears in some other struct's {@code merged_from} list</li>
 *   <li>Its UUID is not referenced by any inference in the current batch
 *       or the deferred-type-inference queue</li>
 *   <li>Its resolved Ghidra DataType has no remaining program usage
 *       (function signatures, locals, defined data, parent composites)</li>
 * </ol>
 */
public class MergedStructCleaner {

    // TEMP_DEBUG_LOGGING: keep until merged-struct retention diagnosis is complete,
    // then delete these constants + associated logs (search for "TEMP_DEBUG").
    private static final boolean TEMP_DEBUG_LOG_BLOCKERS = true;
    private static final int TEMP_DEBUG_MAX_BLOCKER_LOGS_PER_RUN = 8;

    private final InferenceStorage inferenceStorage;
    private final StructInferenceApplier structInferenceApplier;

    public MergedStructCleaner(InferenceStorage inferenceStorage,
                               StructInferenceApplier structInferenceApplier) {
        this.inferenceStorage = inferenceStorage;
        this.structInferenceApplier = structInferenceApplier;
    }

    private static final class UsedTypeIndex {
        final Set<DataType> usedTypes;
        final Map<DataType, String> sampleByType;

        UsedTypeIndex(Set<DataType> usedTypes, Map<DataType, String> sampleByType) {
            this.usedTypes = usedTypes;
            this.sampleByType = sampleByType;
        }

        String getSample(DataType type) {
            return sampleByType != null ? sampleByType.get(type) : null;
        }
    }

    private static final class UsageBlocker {
        final String relation;
        final DataType usedType;
        final String sample;

        UsageBlocker(String relation, DataType usedType, String sample) {
            this.relation = relation;
            this.usedType = usedType;
            this.sample = sample;
        }
    }

    /**
     * Run the full cleanup: identify merged candidates, prove they are unused,
     * then delete the data type and prune stored metadata.
     *
     * @param program    the current program
     * @param inferences the inference batch that was just applied (used to
     *                   protect still-referenced struct IDs)
     * @param monitor    task monitor for cancellation
     */
    public void cleanupMergedOrphanStructs(Program program,
                                           List<Inference> inferences,
                                           TaskMonitor monitor) {
        if (program == null || program.isClosed()) {
            return;
        }

        Set<UUID> candidates = computeCandidates(inferences);
        if (candidates.isEmpty()) {
            return;
        }

        UsedTypeIndex usedIndex = collectUsedDataTypes(program, monitor);
        if (monitor != null && monitor.isCancelled()) {
            return;
        }

        DataTypeManager dtm = program.getDataTypeManager();
        List<DataType> toDelete = new ArrayList<>();
        // Keep IDs aligned with toDelete (same index).
        List<UUID> toDeleteIds = new ArrayList<>();
        // Metadata to prune even if we couldn't resolve a DataType (stale properties).
        List<UUID> metaOnlyPruneIds = new ArrayList<>();
        int skippedUsed = 0;
        int skippedParent = 0;
        int resolvedMissingDataType = 0;
        int debugLoggedBlockers = 0;

        for (UUID candidateId : candidates) {
            if (monitor != null && monitor.isCancelled()) {
                return;
            }
            DataType dt = resolveStructDataType(program, candidateId);
            if (dt == null) {
                // No type to remove from DTM; prune our metadata so we don't keep retrying.
                metaOnlyPruneIds.add(candidateId);
                resolvedMissingDataType++;
                continue;
            }

            UsageBlocker blocker = findUsageBlocker(dt, usedIndex, candidates, program);
            if (blocker != null) {
                skippedUsed++;
                if (TEMP_DEBUG_LOG_BLOCKERS && debugLoggedBlockers < TEMP_DEBUG_MAX_BLOCKER_LOGS_PER_RUN) {
                    debugLoggedBlockers++;
                    Msg.info(this, "TEMP_DEBUG[MergedStructCleaner] not deleting merged-from struct id=" + candidateId
                        + " dt=" + dt.getPathName()
                        + " because relation=" + blocker.relation
                        + " usedType=" + (blocker.usedType != null ? blocker.usedType.getPathName() : "null")
                        + (blocker.sample != null ? " sample=" + blocker.sample : ""));
                }
                continue;
            }

            Collection<DataType> parents = dt.getParents();
            DataType nonCandidateParent = findNonCandidateParent(parents, candidates, program);
            if (nonCandidateParent != null) {
                skippedParent++;
                if (TEMP_DEBUG_LOG_BLOCKERS && debugLoggedBlockers < TEMP_DEBUG_MAX_BLOCKER_LOGS_PER_RUN) {
                    debugLoggedBlockers++;
                    Msg.info(this, "TEMP_DEBUG[MergedStructCleaner] not deleting merged-from struct id=" + candidateId
                        + " dt=" + dt.getPathName()
                        + " because nonCandidateParent=" + nonCandidateParent.getPathName());
                }
                continue;
            }

            toDelete.add(dt);
            toDeleteIds.add(candidateId);
        }

        if (toDelete.isEmpty() && metaOnlyPruneIds.isEmpty()) {
            // TEMP_DEBUG: always emit a summary so "candidates exist but nothing removed"
            // doesn't look like a silent no-op.
            Msg.info(this,
                "Merged-struct cleanup: candidates=" + candidates.size()
                    + ", removed=0"
                    + ", skippedUsed=" + skippedUsed
                    + ", skippedParent=" + skippedParent
                    + ", missingDataType=" + resolvedMissingDataType
                    + ", removeFailed=0"
                    + ", metadataPrunedOk=0"
                    + ", metadataPrunedFailed=0");
            return;
        }

        List<UUID> removedIds = new ArrayList<>();
        List<UUID> failedRemoveIds = new ArrayList<>();
        if (!toDelete.isEmpty()) {
            TransactionUtils.runInTransaction(program, "Zenyard: Remove merged orphan structs", () -> {
                for (int i = 0; i < toDelete.size(); i++) {
                    DataType dt = toDelete.get(i);
                    UUID id = toDeleteIds.get(i);
                    try {
                        dtm.remove(dt);
                        removedIds.add(id);
                    } catch (Exception e) {
                        failedRemoveIds.add(id);
                        Msg.warn(this, "Failed to remove merged struct '" + dt.getName()
                            + "' (id=" + id + "): " + e.getMessage());
                    }
                }
            });
        }

        // Only prune metadata for successful removals (plus meta-only removals).
        List<UUID> pruneIds = new ArrayList<>(removedIds.size() + metaOnlyPruneIds.size());
        pruneIds.addAll(removedIds);
        pruneIds.addAll(metaOnlyPruneIds);

        int prunedOk = 0;
        int prunedFailed = 0;
        for (UUID id : pruneIds) {
            try {
                inferenceStorage.removeStructMetadata(id);
                prunedOk++;
            } catch (Exception e) {
                Msg.warn(this, "Failed to prune metadata for struct id="
                    + id + ": " + e.getMessage());
                prunedFailed++;
            }
        }

        Msg.info(this,
            "Merged-struct cleanup: candidates=" + candidates.size()
                + ", removed=" + removedIds.size()
                + ", skippedUsed=" + skippedUsed
                + ", skippedParent=" + skippedParent
                + ", missingDataType=" + resolvedMissingDataType
                + ", removeFailed=" + failedRemoveIds.size()
                + ", metadataPrunedOk=" + prunedOk
                + ", metadataPrunedFailed=" + prunedFailed);
    }

    // ------------------------------------------------------------------
    // Step 1: Identify deletion candidates
    // ------------------------------------------------------------------

    Set<UUID> computeCandidates(List<Inference> currentBatch) {
        Map<UUID, StructDefinition> registry =
            inferenceStorage.getStructRegistryDefinitions();

        Set<UUID> mergedChildren = new HashSet<>();
        for (StructDefinition def : registry.values()) {
            List<UUID> mf = def.getMergedFrom();
            if (mf != null) {
                mergedChildren.addAll(mf);
            }
        }
        if (mergedChildren.isEmpty()) {
            return Set.of();
        }

        // Only protect IDs referenced by the current batch + deferred type inference queue.
        // Do NOT treat "everything in the registry" as referenced, otherwise merged children
        // become permanent non-candidates and cleanup never runs.
        Set<UUID> referenced = collectReferencedStructIds(currentBatch);
        int mergedChildrenCount = mergedChildren.size();
        mergedChildren.removeAll(referenced);
        Msg.info(this, "Merged-struct cleanup: merged_from children=" + mergedChildrenCount
            + ", protectedReferenced=" + referenced.size()
            + ", candidates=" + mergedChildren.size());
        return mergedChildren;
    }

    private Set<UUID> collectReferencedStructIds(List<Inference> currentBatch) {
        Set<UUID> referenced = new HashSet<>();

        if (currentBatch != null) {
            for (Inference inference : currentBatch) {
                Object actual = inference.getActualInstance();
                if (actual instanceof StructDefinition) {
                    StructDefinition sd = (StructDefinition) actual;
                    if (sd.getId() != null) {
                        referenced.add(sd.getId());
                    }
                    if (sd.getFieldDefinitions() != null) {
                        for (FieldDefinition field : sd.getFieldDefinitions()) {
                            if (field != null && field.getStructId() != null) {
                                referenced.add(field.getStructId());
                            }
                        }
                    }
                } else if (actual instanceof ParameterType) {
                    UUID sid = ((ParameterType) actual).getStructId();
                    if (sid != null) {
                        referenced.add(sid);
                    }
                } else if (actual instanceof ReturnType) {
                    UUID sid = ((ReturnType) actual).getStructId();
                    if (sid != null) {
                        referenced.add(sid);
                    }
                }
            }
        }

        for (InferenceStorage.DeferredTypeInferenceRecord rec :
                inferenceStorage.getDeferredTypeInferences()) {
            if (rec.getParameterType() != null
                    && rec.getParameterType().getStructId() != null) {
                referenced.add(rec.getParameterType().getStructId());
            }
            if (rec.getReturnType() != null
                    && rec.getReturnType().getStructId() != null) {
                referenced.add(rec.getReturnType().getStructId());
            }
        }

        return referenced;
    }

    // ------------------------------------------------------------------
    // Step 2: Prove "unused in program"
    // ------------------------------------------------------------------

    private UsedTypeIndex collectUsedDataTypes(Program program, TaskMonitor monitor) {
        Set<DataType> used = new HashSet<>();
        Map<DataType, String> samples = TEMP_DEBUG_LOG_BLOCKERS ? new HashMap<>() : null;
        FunctionIterator functions =
            program.getFunctionManager().getFunctions(true);

        while (functions.hasNext()) {
            if (monitor != null && monitor.isCancelled()) {
                return new UsedTypeIndex(used, samples);
            }
            Function function = functions.next();
            DataType retType = function.getReturnType();
            if (retType != null) {
                if (used.add(retType) && samples != null) {
                    samples.put(retType, "function=" + function.getEntryPoint() + " return_type");
                }
            }
            for (Parameter param : function.getParameters()) {
                DataType pType = param.getDataType();
                if (pType != null) {
                    if (used.add(pType) && samples != null) {
                        samples.put(pType, "function=" + function.getEntryPoint()
                            + " param name=" + param.getName());
                    }
                }
            }
            for (Variable local : function.getLocalVariables()) {
                DataType lType = local.getDataType();
                if (lType != null) {
                    if (used.add(lType) && samples != null) {
                        samples.put(lType, "function=" + function.getEntryPoint()
                            + " local name=" + local.getName());
                    }
                }
            }
        }

        DataIterator dataIterator =
            program.getListing().getDefinedData(true);
        while (dataIterator.hasNext()) {
            if (monitor != null && monitor.isCancelled()) {
                return new UsedTypeIndex(used, samples);
            }
            Data data = dataIterator.next();
            DataType dType = data.getDataType();
            if (dType != null) {
                if (used.add(dType) && samples != null) {
                    samples.put(dType, "defined_data=" + data.getAddress());
                }
            }
        }

        return new UsedTypeIndex(used, samples);
    }

    private UsageBlocker findUsageBlocker(
            DataType candidate,
            UsedTypeIndex usedIndex,
            Set<UUID> candidateIds,
            Program program) {
        for (DataType used : usedIndex.usedTypes) {
            if (used.equals(candidate)) {
                return new UsageBlocker("direct", used, usedIndex.getSample(used));
            }
            if (used.dependsOn(candidate)) {
                if (!isUsedTypeAlsoCandidate(used, candidateIds, program)) {
                    return new UsageBlocker("dependsOn", used, usedIndex.getSample(used));
                }
            }
        }
        return null;
    }

    private boolean isUsedTypeAlsoCandidate(DataType usedType,
                                            Set<UUID> candidateIds,
                                            Program program) {
        for (UUID cid : candidateIds) {
            DataType cdt = resolveStructDataType(program, cid);
            if (cdt != null && cdt.equals(usedType)) {
                return true;
            }
        }
        return false;
    }

    private DataType findNonCandidateParent(
            Collection<DataType> parents,
            Set<UUID> candidateIds,
            Program program) {
        if (parents == null || parents.isEmpty()) {
            return null;
        }
        for (DataType parent : parents) {
            if (!isUsedTypeAlsoCandidate(parent, candidateIds, program)) {
                return parent;
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private DataType resolveStructDataType(Program program, UUID structId) {
        return structInferenceApplier.resolveStructTypeById(program, structId);
    }
}
