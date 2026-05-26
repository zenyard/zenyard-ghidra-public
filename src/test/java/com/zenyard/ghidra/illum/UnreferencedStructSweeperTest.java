package com.zenyard.ghidra.illum;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import com.zenyard.ghidra.api.generated.model.StructDefinition;
import com.zenyard.ghidra.storage.InferenceStorage;

import ghidra.framework.options.Options;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.util.task.TaskMonitor;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UnreferencedStructSweeperTest {

    private static final CategoryPath ZENYARD_STRUCTS = new CategoryPath("/zenyard/structs");

    @Mock private Program program;
    @Mock private ProgramBasedDataTypeManager dtm;
    @Mock private Category category;
    @Mock private FunctionManager functionManager;
    @Mock private Listing listing;

    private InferenceStorage inferenceStorage;
    private final Map<UUID, String> storedPaths = new HashMap<>();

    @BeforeEach
    void setUp() {
        when(program.isClosed()).thenReturn(false);
        when(program.getDataTypeManager()).thenReturn(dtm);
        when(program.getFunctionManager()).thenReturn(functionManager);
        when(program.getListing()).thenReturn(listing);
        when(dtm.getCategory(ZENYARD_STRUCTS)).thenReturn(category);
        when(dtm.remove(any(DataType.class))).thenReturn(true);

        // Real InferenceStorage backed by a mocked Program/Options — only the methods
        // we exercise (getStructRegistryDefinitions, getStructDataTypePath, removeStructMetadata)
        // are stubbed at the storage seam below.
        inferenceStorage = mock(InferenceStorage.class);
    }

    private StructureDataType newStruct(String name) {
        StructureDataType s = new StructureDataType(ZENYARD_STRUCTS, name, 0, dtm);
        s.insertAtOffset(0, DWordDataType.dataType, 4, "f0", null);
        return s;
    }

    private void seedCategory(DataType... types) {
        when(category.getDataTypes()).thenReturn(types);
    }

    private void seedFunctions(Function... fns) {
        when(functionManager.getFunctions(true)).thenReturn(asIterator(List.of(fns)));
    }

    private void seedDefinedData(Data... data) {
        when(listing.getDefinedData(true)).thenReturn(asDataIterator(List.of(data)));
    }

    private void seedStorageOwner(UUID id, DataType dt) {
        Map<UUID, StructDefinition> reg = new HashMap<>();
        StructDefinition def = new StructDefinition();
        def.setId(id);
        reg.put(id, def);
        when(inferenceStorage.getStructRegistryDefinitions()).thenReturn(reg);
        when(inferenceStorage.getStructDataTypePath(id)).thenReturn(dt.getPathName());
        storedPaths.put(id, dt.getPathName());
    }

    @Test
    void removes_struct_with_zero_references() {
        StructureDataType doomed = newStruct("Orphan");
        seedCategory(doomed);
        seedFunctions();
        seedDefinedData();
        UUID id = UUID.randomUUID();
        seedStorageOwner(id, doomed);

        int removed = new UnreferencedStructSweeper(inferenceStorage)
            .sweep(program, TaskMonitor.DUMMY);

        assertEquals(1, removed);
        verify(dtm).remove(doomed);
        verify(inferenceStorage).removeStructMetadata(id);
    }

    @Test
    void keeps_struct_used_as_function_parameter() {
        StructureDataType used = newStruct("UsedAsParam");
        seedCategory(used);

        Function fn = mock(Function.class);
        when(fn.getReturnType()).thenReturn(DWordDataType.dataType);
        Parameter p = mock(Parameter.class);
        when(p.getDataType()).thenReturn(used);
        when(fn.getParameters()).thenReturn(new Parameter[]{p});
        when(fn.getLocalVariables()).thenReturn(new Variable[]{});
        seedFunctions(fn);
        seedDefinedData();
        UUID id = UUID.randomUUID();
        seedStorageOwner(id, used);

        int removed = new UnreferencedStructSweeper(inferenceStorage)
            .sweep(program, TaskMonitor.DUMMY);

        assertEquals(0, removed);
        verify(dtm, never()).remove(any(DataType.class));
        verify(inferenceStorage, never()).removeStructMetadata(any(UUID.class));
    }

    @Test
    void keeps_struct_used_as_local_variable() {
        StructureDataType used = newStruct("UsedAsLocal");
        seedCategory(used);

        Function fn = mock(Function.class);
        when(fn.getReturnType()).thenReturn(DWordDataType.dataType);
        when(fn.getParameters()).thenReturn(new Parameter[]{});
        Variable v = mock(Variable.class);
        when(v.getDataType()).thenReturn(used);
        when(fn.getLocalVariables()).thenReturn(new Variable[]{v});
        seedFunctions(fn);
        seedDefinedData();
        UUID id = UUID.randomUUID();
        seedStorageOwner(id, used);

        int removed = new UnreferencedStructSweeper(inferenceStorage)
            .sweep(program, TaskMonitor.DUMMY);

        assertEquals(0, removed);
        verify(dtm, never()).remove(any(DataType.class));
    }

    @Test
    void keeps_struct_used_via_pointer_in_function_signature() {
        StructureDataType target = newStruct("PointedAt");
        seedCategory(target);
        PointerDataType ptr = new PointerDataType(target, 8, dtm);

        Function fn = mock(Function.class);
        when(fn.getReturnType()).thenReturn(ptr);
        when(fn.getParameters()).thenReturn(new Parameter[]{});
        when(fn.getLocalVariables()).thenReturn(new Variable[]{});
        seedFunctions(fn);
        seedDefinedData();
        UUID id = UUID.randomUUID();
        seedStorageOwner(id, target);

        int removed = new UnreferencedStructSweeper(inferenceStorage)
            .sweep(program, TaskMonitor.DUMMY);

        assertEquals(0, removed);
        verify(dtm, never()).remove(any(DataType.class));
    }

    @Test
    void keeps_struct_used_as_defined_data_type() {
        StructureDataType used = newStruct("UsedAsGlobal");
        seedCategory(used);
        seedFunctions();

        Data d = mock(Data.class);
        when(d.getDataType()).thenReturn(used);
        seedDefinedData(d);
        UUID id = UUID.randomUUID();
        seedStorageOwner(id, used);

        int removed = new UnreferencedStructSweeper(inferenceStorage)
            .sweep(program, TaskMonitor.DUMMY);

        assertEquals(0, removed);
        verify(dtm, never()).remove(any(DataType.class));
    }

    @Test
    void keeps_struct_transitively_referenced_as_field_of_in_use_parent() {
        StructureDataType child = newStruct("Child");
        StructureDataType parent = new StructureDataType(ZENYARD_STRUCTS, "Parent", 0, dtm);
        parent.insertAtOffset(0, child, child.getLength(), "kid", null);
        seedCategory(parent, child);

        Function fn = mock(Function.class);
        Parameter p = mock(Parameter.class);
        when(p.getDataType()).thenReturn(parent);
        when(fn.getReturnType()).thenReturn(DWordDataType.dataType);
        when(fn.getParameters()).thenReturn(new Parameter[]{p});
        when(fn.getLocalVariables()).thenReturn(new Variable[]{});
        seedFunctions(fn);
        seedDefinedData();
        when(inferenceStorage.getStructRegistryDefinitions()).thenReturn(Collections.emptyMap());

        int removed = new UnreferencedStructSweeper(inferenceStorage)
            .sweep(program, TaskMonitor.DUMMY);

        assertEquals(0, removed);
        verify(dtm, never()).remove(any(DataType.class));
    }

    @Test
    void removes_only_truly_unreferenced_in_mixed_category() {
        StructureDataType orphan = newStruct("Orphan");
        StructureDataType kept = newStruct("Kept");
        seedCategory(orphan, kept);

        Function fn = mock(Function.class);
        Parameter p = mock(Parameter.class);
        when(p.getDataType()).thenReturn(kept);
        when(fn.getReturnType()).thenReturn(DWordDataType.dataType);
        when(fn.getParameters()).thenReturn(new Parameter[]{p});
        when(fn.getLocalVariables()).thenReturn(new Variable[]{});
        seedFunctions(fn);
        seedDefinedData();
        UUID idOrphan = UUID.randomUUID();
        UUID idKept = UUID.randomUUID();
        Map<UUID, StructDefinition> reg = new HashMap<>();
        StructDefinition d1 = new StructDefinition(); d1.setId(idOrphan); reg.put(idOrphan, d1);
        StructDefinition d2 = new StructDefinition(); d2.setId(idKept); reg.put(idKept, d2);
        when(inferenceStorage.getStructRegistryDefinitions()).thenReturn(reg);
        when(inferenceStorage.getStructDataTypePath(idOrphan)).thenReturn(orphan.getPathName());
        when(inferenceStorage.getStructDataTypePath(idKept)).thenReturn(kept.getPathName());

        int removed = new UnreferencedStructSweeper(inferenceStorage)
            .sweep(program, TaskMonitor.DUMMY);

        assertEquals(1, removed);
        verify(dtm).remove(orphan);
        verify(dtm, never()).remove(kept);
        verify(inferenceStorage).removeStructMetadata(idOrphan);
        verify(inferenceStorage, never()).removeStructMetadata(idKept);
    }

    @Test
    void does_not_prune_metadata_when_dtm_remove_returns_false() {
        StructureDataType doomed = newStruct("StuckOrphan");
        seedCategory(doomed);
        seedFunctions();
        seedDefinedData();
        UUID id = UUID.randomUUID();
        seedStorageOwner(id, doomed);
        when(dtm.remove(doomed)).thenReturn(false);

        int removed = new UnreferencedStructSweeper(inferenceStorage)
            .sweep(program, TaskMonitor.DUMMY);

        assertEquals(0, removed);
        verify(dtm).remove(doomed);
        verify(inferenceStorage, never()).removeStructMetadata(any(UUID.class));
    }

    @Test
    void no_op_when_program_closed() {
        when(program.isClosed()).thenReturn(true);
        int removed = new UnreferencedStructSweeper(inferenceStorage)
            .sweep(program, TaskMonitor.DUMMY);
        assertEquals(0, removed);
        verify(dtm, never()).remove(any(DataType.class));
    }

    @Test
    void no_op_when_category_missing() {
        when(dtm.getCategory(ZENYARD_STRUCTS)).thenReturn(null);
        int removed = new UnreferencedStructSweeper(inferenceStorage)
            .sweep(program, TaskMonitor.DUMMY);
        assertEquals(0, removed);
        verify(dtm, never()).remove(any(DataType.class));
    }

    @Test
    void addReachable_handles_self_referential_struct_without_looping() {
        StructureDataType node = new StructureDataType(ZENYARD_STRUCTS, "Node", 0, dtm);
        PointerDataType selfPtr = new PointerDataType(node, 8, dtm);
        node.insertAtOffset(0, selfPtr, 8, "next", null);

        Set<DataType> set = new java.util.HashSet<>();
        UnreferencedStructSweeper.addReachable(set, node);

        assertTrue(set.contains(node));
        assertTrue(set.contains(selfPtr));
    }

    @Test
    void addReachable_does_nothing_for_null() {
        Set<DataType> set = new java.util.HashSet<>();
        UnreferencedStructSweeper.addReachable(set, null);
        assertTrue(set.isEmpty());
    }

    @Test
    void addReachable_walks_pointer_to_target() {
        StructureDataType target = newStruct("Target");
        PointerDataType ptr = new PointerDataType(target, 8, dtm);
        Set<DataType> set = new java.util.HashSet<>();
        UnreferencedStructSweeper.addReachable(set, ptr);
        assertTrue(set.contains(ptr));
        assertTrue(set.contains(target));
    }

    // --- iterator helpers -------------------------------------------------

    private static FunctionIterator asIterator(List<Function> fns) {
        Iterator<Function> it = fns.iterator();
        return new FunctionIterator() {
            @Override public boolean hasNext() { return it.hasNext(); }
            @Override public Function next() { return it.next(); }
            @Override public Iterator<Function> iterator() { return this; }
        };
    }

    private static DataIterator asDataIterator(List<Data> data) {
        Iterator<Data> it = data.iterator();
        return new DataIterator() {
            @Override public boolean hasNext() { return it.hasNext(); }
            @Override public Data next() { return it.next(); }
            @Override public Iterator<Data> iterator() { return this; }
        };
    }

    @SuppressWarnings("unused")
    private static void unused(Object... ignored) {
        // keep imports tight
        assertFalse(false);
    }
}
