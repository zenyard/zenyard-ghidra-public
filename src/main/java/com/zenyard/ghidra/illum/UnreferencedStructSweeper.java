package com.zenyard.ghidra.illum;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.zenyard.ghidra.api.generated.model.StructDefinition;
import com.zenyard.ghidra.storage.InferenceStorage;
import com.zenyard.ghidra.util.TransactionUtils;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
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
 * Removes inferred Structures from {@code /zenyard/structs/} that have no
 * remaining references in the program.
 *
 * <p>Runs at the drain point of {@link com.zenyard.ghidra.polling.ApplyInferencesTask}
 * after the inference queue empties, so the only structs in the DTM are ones that
 * either survived all inference application or were left behind because no inference
 * ever wired them into a function signature, global, local, or other type.
 *
 * <p>This pass is reference-state driven, not metadata driven. It complements
 * {@link MergedStructCleaner} (which evicts via {@code merged_from} ancestry): a struct
 * that has no merged_from parent and no DTM references would otherwise persist forever.
 */
public final class UnreferencedStructSweeper {

    private static final CategoryPath STRUCT_CATEGORY = new CategoryPath("/zenyard/structs");

    private final InferenceStorage inferenceStorage;

    public UnreferencedStructSweeper(InferenceStorage inferenceStorage) {
        this.inferenceStorage = inferenceStorage;
    }

    /**
     * Sweep unreferenced structs in {@code /zenyard/structs/}. No-op if the program
     * is null, closed, or the monitor is cancelled.
     *
     * @return the count of structs removed.
     */
    public int sweep(Program program, TaskMonitor monitor) {
        if (program == null || program.isClosed()) {
            return 0;
        }
        if (monitor != null && monitor.isCancelled()) {
            return 0;
        }

        long startMs = System.currentTimeMillis();
        DataTypeManager dtm = program.getDataTypeManager();
        Category category = dtm.getCategory(STRUCT_CATEGORY);
        if (category == null) {
            return 0;
        }

        Set<DataType> inUse = buildInUseClosure(program, monitor);
        if (monitor != null && monitor.isCancelled()) {
            return 0;
        }

        Map<String, UUID> uuidByPath = buildPathToUuidMap();

        List<DataType> doomed = new ArrayList<>();
        int scanned = 0;
        for (DataType dt : category.getDataTypes()) {
            if (monitor != null && monitor.isCancelled()) {
                return 0;
            }
            if (!(dt instanceof Structure)) {
                continue;
            }
            scanned++;
            if (inUse.contains(dt)) {
                continue;
            }
            doomed.add(dt);
        }

        if (doomed.isEmpty()) {
            Msg.info(this,
                "Unreferenced-struct sweep: scanned=" + scanned
                    + ", inUse=" + inUse.size()
                    + ", removed=0, failed=0, durationMs="
                    + (System.currentTimeMillis() - startMs));
            return 0;
        }

        int[] removed = { 0 };
        int[] failed = { 0 };
        TransactionUtils.runInTransaction(program, "Zenyard: Sweep unreferenced structs", () -> {
            for (DataType dt : doomed) {
                if (monitor != null && monitor.isCancelled()) {
                    return;
                }
                String pathName = dt.getPathName();
                UUID owner = uuidByPath.get(pathName);
                try {
                    boolean ok = dtm.remove(dt);
                    if (!ok) {
                        Msg.warn(this, "dtm.remove returned false for '" + pathName + "'");
                        failed[0]++;
                        continue;
                    }
                    if (owner != null) {
                        inferenceStorage.removeStructMetadata(owner);
                    }
                    removed[0]++;
                } catch (Exception e) {
                    Msg.warn(this, "Failed removing '" + pathName + "': " + e.getMessage());
                    failed[0]++;
                }
            }
        });

        Msg.info(this,
            "Unreferenced-struct sweep: scanned=" + scanned
                + ", inUse=" + inUse.size()
                + ", removed=" + removed[0]
                + ", failed=" + failed[0]
                + ", durationMs=" + (System.currentTimeMillis() - startMs));
        return removed[0];
    }

    private Map<String, UUID> buildPathToUuidMap() {
        Map<UUID, StructDefinition> registry = inferenceStorage.getStructRegistryDefinitions();
        Map<String, UUID> out = new HashMap<>(registry.size() * 2);
        for (UUID id : registry.keySet()) {
            if (id == null) {
                continue;
            }
            String path = inferenceStorage.getStructDataTypePath(id);
            if (path != null && !path.isEmpty()) {
                out.put(path, id);
            }
        }
        return out;
    }

    private Set<DataType> buildInUseClosure(Program program, TaskMonitor monitor) {
        Set<DataType> inUse = new HashSet<>();

        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            if (monitor != null && monitor.isCancelled()) {
                return inUse;
            }
            Function fn = functions.next();
            if (fn == null) {
                continue;
            }
            addReachable(inUse, fn.getReturnType());
            for (Parameter p : fn.getParameters()) {
                if (p != null) {
                    addReachable(inUse, p.getDataType());
                }
            }
            for (Variable v : fn.getLocalVariables()) {
                if (v != null) {
                    addReachable(inUse, v.getDataType());
                }
            }
        }

        DataIterator data = program.getListing().getDefinedData(true);
        while (data.hasNext()) {
            if (monitor != null && monitor.isCancelled()) {
                return inUse;
            }
            Data d = data.next();
            if (d != null) {
                addReachable(inUse, d.getDataType());
            }
        }

        return inUse;
    }

    static void addReachable(Set<DataType> set, DataType dt) {
        if (dt == null || !set.add(dt)) {
            return;
        }
        if (dt instanceof Pointer) {
            addReachable(set, ((Pointer) dt).getDataType());
        } else if (dt instanceof Array) {
            addReachable(set, ((Array) dt).getDataType());
        } else if (dt instanceof TypeDef) {
            addReachable(set, ((TypeDef) dt).getDataType());
        } else if (dt instanceof Composite) {
            for (DataTypeComponent c : ((Composite) dt).getComponents()) {
                if (c != null) {
                    addReachable(set, c.getDataType());
                }
            }
        } else if (dt instanceof FunctionDefinition) {
            FunctionDefinition fdef = (FunctionDefinition) dt;
            addReachable(set, fdef.getReturnType());
            ParameterDefinition[] args = fdef.getArguments();
            if (args != null) {
                for (ParameterDefinition arg : args) {
                    if (arg != null) {
                        addReachable(set, arg.getDataType());
                    }
                }
            }
        } else if (dt instanceof BitFieldDataType) {
            addReachable(set, ((BitFieldDataType) dt).getBaseDataType());
        }
    }
}
