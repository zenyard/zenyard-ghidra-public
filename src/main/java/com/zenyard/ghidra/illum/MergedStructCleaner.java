package com.zenyard.ghidra.illum;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.zenyard.ghidra.api.generated.model.FieldDefinition;
import com.zenyard.ghidra.api.generated.model.GlobalVariableType;
import com.zenyard.ghidra.api.generated.model.Inference;
import com.zenyard.ghidra.api.generated.model.ParameterType;
import com.zenyard.ghidra.api.generated.model.ReturnType;
import com.zenyard.ghidra.api.generated.model.StructDefinition;
import com.zenyard.ghidra.storage.InferenceStorage;
import com.zenyard.ghidra.util.TransactionUtils;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Replaces inferred structs that have been superseded by backend merging.
 *
 * <p><b>Merge direction:</b> When a struct <b>X</b> has {@code merged_from: [A, B]}, it means
 * the backend merged structs A and B <b>into</b> X. So <b>X is the canonical struct we keep</b>;
 * A and B are the old structs we replace and remove. This cleaner does <b>not</b> remove X
 * (the struct that has merged_from). It only removes A and B (the IDs listed inside merged_from).
 *
 * <p>For each such old struct (child), we replace all program references to it with the
 * merged-into struct (parent) via {@code DataTypeManager.replaceDataType}, then prune
 * stored metadata for the child.
 *
 * <p>A struct is eligible for replacement (i.e. it is a "child") only when:
 * <ol>
 *   <li>Its UUID appears in <b>some other</b> struct's {@code merged_from} list</li>
 *   <li>Its UUID is not referenced by any inference in the current batch
 *       or the deferred-type-inference queue</li>
 * </ol>
 *
 * <p>Using {@code replaceDataType} instead of {@code remove} ensures that all
 * derived references (pointer wrappers, function signatures, local variables,
 * composite fields) are atomically rewritten to the merged-into struct,
 * eliminating the stale-pointer-blocker problem that prevented deletion.
 */
public class MergedStructCleaner {

    private final InferenceStorage inferenceStorage;
    private final StructInferenceApplier structInferenceApplier;

    public MergedStructCleaner(InferenceStorage inferenceStorage,
                               StructInferenceApplier structInferenceApplier) {
        this.inferenceStorage = inferenceStorage;
        this.structInferenceApplier = structInferenceApplier;
    }

    /**
     * Run the full cleanup: identify merged candidates, replace their program
     * references with the merged-into struct, then prune stored metadata.
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

        Map<UUID, UUID> childToParent = buildMergedFromMapping();
        Set<UUID> candidates = computeCandidates(inferences, childToParent);
        if (candidates.isEmpty()) {
            return;
        }

        DataTypeManager dtm = program.getDataTypeManager();
        List<UUID> pruneIds = new ArrayList<>();
        int replaced = 0;
        int missingOldType = 0;
        int missingNewType = 0;
        int replaceFailed = 0;

        List<UUID> replaceIds = new ArrayList<>();
        List<DataType> replaceOldTypes = new ArrayList<>();
        List<DataType> replaceNewTypes = new ArrayList<>();

        for (UUID candidateId : candidates) {
            if (monitor != null && monitor.isCancelled()) {
                return;
            }

            DataType oldDt = resolveStructDataType(program, candidateId);
            if (oldDt == null) {
                pruneIds.add(candidateId);
                missingOldType++;
                continue;
            }

            UUID parentId = childToParent.get(candidateId);
            if (parentId == null) {
                replaceFailed++;
                continue;
            }

            DataType newDt = resolveStructDataType(program, parentId);
            if (newDt == null) {
                missingNewType++;
                Msg.warn(this, "Cannot replace merged struct '" + oldDt.getName()
                    + "' (id=" + candidateId + "): merged-into struct id=" + parentId
                    + " could not be resolved");
                continue;
            }

            replaceIds.add(candidateId);
            replaceOldTypes.add(oldDt);
            replaceNewTypes.add(newDt);
        }

        if (!replaceOldTypes.isEmpty()) {
            final int[] successCount = {0};
            TransactionUtils.runInTransaction(program, "Zenyard: Replace merged structs", () -> {
                for (int i = 0; i < replaceOldTypes.size(); i++) {
                    DataType oldDt = replaceOldTypes.get(i);
                    DataType newDt = replaceNewTypes.get(i);
                    UUID id = replaceIds.get(i);
                    try {
                        dtm.replaceDataType(oldDt, newDt, false);
                        pruneIds.add(id);
                        successCount[0]++;
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to replace merged struct '"
                            + oldDt.getName() + "' (id=" + id + ") with '"
                            + newDt.getName() + "': " + e.getMessage());
                    }
                }
            });
            replaced = successCount[0];
        }

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

        if (!pruneIds.isEmpty()) {
            try {
                inferenceStorage.scrubMergedFromReferences(new HashSet<>(pruneIds));
            } catch (Exception e) {
                Msg.warn(this, "Failed to scrub merged_from references: " + e.getMessage());
            }
        }

        Msg.info(this,
            "Merged-struct cleanup: candidates=" + candidates.size()
                + ", replaced=" + replaced
                + ", missingOldType=" + missingOldType
                + ", missingNewType=" + missingNewType
                + ", replaceFailed=" + replaceFailed
                + ", metadataPrunedOk=" + prunedOk
                + ", metadataPrunedFailed=" + prunedFailed);
    }

    // ------------------------------------------------------------------
    // Step 1: Build child -> parent mapping (child = in merged_from; parent = struct that has merged_from)
    // ------------------------------------------------------------------

    private Map<UUID, UUID> buildMergedFromMapping() {
        Map<UUID, StructDefinition> registry =
            inferenceStorage.getStructRegistryDefinitions();
        Map<UUID, UUID> childToParent = new HashMap<>();
        for (Map.Entry<UUID, StructDefinition> entry : registry.entrySet()) {
            List<UUID> mf = entry.getValue().getMergedFrom();
            if (mf != null) {
                UUID parentId = entry.getKey(); // struct that has merged_from is the parent we keep
                for (UUID childId : mf) {
                    childToParent.put(childId, parentId); // child gets replaced by parent, then removed
                }
            }
        }
        return childToParent;
    }

    // ------------------------------------------------------------------
    // Step 2: Identify replacement candidates
    // ------------------------------------------------------------------

    Set<UUID> computeCandidates(List<Inference> currentBatch,
                                Map<UUID, UUID> childToParent) {
        Set<UUID> mergedChildren = new HashSet<>(childToParent.keySet());
        if (mergedChildren.isEmpty()) {
            return Set.of();
        }

        Set<UUID> referenced = collectReferencedStructIds(
            currentBatch,
            inferenceStorage != null ? inferenceStorage.getDeferredTypeInferences() : List.of()
        );
        int mergedChildrenCount = mergedChildren.size();
        mergedChildren.removeAll(referenced);
        Msg.info(this, "Merged-struct cleanup: merged_from children=" + mergedChildrenCount
            + ", protectedReferenced=" + referenced.size()
            + ", candidates=" + mergedChildren.size());
        return mergedChildren;
    }

    Set<UUID> collectReferencedStructIds(
            List<Inference> currentBatch,
            List<InferenceStorage.DeferredTypeInferenceRecord> deferredRecords) {
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
                } else if (actual instanceof GlobalVariableType) {
                    UUID sid = ((GlobalVariableType) actual).getStructId();
                    if (sid != null) {
                        referenced.add(sid);
                    }
                }
            }
        }

        for (InferenceStorage.DeferredTypeInferenceRecord rec : deferredRecords) {
            if (rec.getParameterType() != null
                    && rec.getParameterType().getStructId() != null) {
                referenced.add(rec.getParameterType().getStructId());
            }
            if (rec.getReturnType() != null
                    && rec.getReturnType().getStructId() != null) {
                referenced.add(rec.getReturnType().getStructId());
            }
            if (rec.getGlobalVariableType() != null
                    && rec.getGlobalVariableType().getStructId() != null) {
                referenced.add(rec.getGlobalVariableType().getStructId());
            }
        }

        return referenced;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private DataType resolveStructDataType(Program program, UUID structId) {
        return structInferenceApplier.resolveStructTypeById(program, structId);
    }
}
