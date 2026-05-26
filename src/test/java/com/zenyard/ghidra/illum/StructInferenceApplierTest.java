package com.zenyard.ghidra.illum;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;

import org.junit.jupiter.api.Test;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

class StructInferenceApplierTest {

    private static class _FakeDataTypeManagerState {
        private final CategoryPath category = new CategoryPath("/zenyard/structs");
        private DataType stored;
        private boolean replaced;

        void setExisting(DataType dataType) {
            this.stored = dataType;
        }
    }

    private static DataTypeManager createFakeDataTypeManager(_FakeDataTypeManagerState state) {
        return (DataTypeManager) Proxy.newProxyInstance(
            StructInferenceApplierTest.class.getClassLoader(),
            new Class<?>[] { DataTypeManager.class },
            (_proxy, method, args) -> {
                String methodName = method.getName();
                if ("getDataType".equals(methodName) && args != null && args.length == 2) {
                    CategoryPath path = (CategoryPath) args[0];
                    String name = (String) args[1];
                    if (state.category.equals(path)
                            && state.stored != null
                            && name.equals(state.stored.getName())) {
                        return state.stored;
                    }
                    return null;
                }
                if ("replaceDataType".equals(methodName) && args != null && args.length == 3) {
                    state.replaced = true;
                    state.stored = (DataType) args[1];
                    return state.stored;
                }
                if ("resolve".equals(methodName) && args != null && args.length == 2) {
                    state.stored = (DataType) args[0];
                    return state.stored;
                }
                if ("getName".equals(methodName)) {
                    return "fake";
                }
                Class<?> returnType = method.getReturnType();
                if (returnType.equals(boolean.class)) {
                    return false;
                }
                if (returnType.equals(int.class)) {
                    return 0;
                }
                if (returnType.equals(long.class)) {
                    return 0L;
                }
                if (returnType.equals(void.class)) {
                    return null;
                }
                return null;
            }
        );
    }

    @Test
    void replaceOrResolveStructureShrinksExistingNamedStruct() throws Exception {
        CategoryPath category = new CategoryPath("/zenyard/structs");
        _FakeDataTypeManagerState state = new _FakeDataTypeManagerState();
        DataTypeManager dtm = createFakeDataTypeManager(state);

        StructureDataType existing =
            new StructureDataType(category, "DefaultSettings", 108);
        state.setExisting(existing);
        assertEquals(108, existing.getLength());

        StructureDataType replacement =
            new StructureDataType(category, "DefaultSettings", 0);
        replacement.insertAtOffset(0, DWordDataType.dataType, 4, "id", null);
        replacement.insertAtOffset(
            4,
            new ArrayDataType(ByteDataType.dataType, 32, 1),
            32,
            "name",
            null
        );
        replacement.insertAtOffset(35, ByteDataType.dataType, 1, "flag_byte", null);
        replacement.insertAtOffset(40, DWordDataType.dataType, 4, "options", null);

        DataType resolved = StructInferenceApplier.replaceOrResolveStructure(
            dtm,
            "DefaultSettings",
            replacement
        );

        Structure resolvedStructure = (Structure) resolved;
        assertTrue(state.replaced);
        assertEquals(replacement.getLength(), resolvedStructure.getLength());
        assertTrue(resolvedStructure.getLength() < existing.getLength());
        assertSame(
            resolvedStructure,
            state.stored
        );
        assertFalse(existing == resolvedStructure);
    }

    @Test
    void insertFieldAtOffsetDoesNotDoubleGrowNonPackedStructure() throws Exception {
        StructureDataType structure =
            new StructureDataType(new CategoryPath("/zenyard/structs"), "Config", 0);

        StructInferenceApplier.insertFieldAtOffset(
            structure,
            0,
            DWordDataType.dataType,
            4,
            "id"
        );
        StructInferenceApplier.insertFieldAtOffset(
            structure,
            4,
            new ArrayDataType(ByteDataType.dataType, 32, 1),
            32,
            "name"
        );
        StructInferenceApplier.insertFieldAtOffset(
            structure,
            36,
            DWordDataType.dataType,
            4,
            "value"
        );
        StructInferenceApplier.insertFieldAtOffset(
            structure,
            40,
            DWordDataType.dataType,
            4,
            "flags"
        );

        assertEquals(44, structure.getLength());
    }

    @Test
    void rewriteOpenArraysAsPointers_leaves_fixed_numeric_array_suffix() {
        assertEquals("uint8_t[19]", StructInferenceApplier.rewriteOpenArraysAsPointers("uint8_t[19]"));
        assertEquals("int16_t[0]", StructInferenceApplier.rewriteOpenArraysAsPointers("int16_t[0]"));
    }

    @Test
    void rewriteOpenArraysAsPointers_maps_empty_brackets_to_star() {
        assertEquals("uint8_t*", StructInferenceApplier.rewriteOpenArraysAsPointers("uint8_t[]"));
        assertEquals("char*", StructInferenceApplier.rewriteOpenArraysAsPointers("char[]"));
        assertEquals("char**", StructInferenceApplier.rewriteOpenArraysAsPointers("char*[]"));
        assertEquals("struct TypeEntry**", StructInferenceApplier.rewriteOpenArraysAsPointers("struct TypeEntry*[]"));
    }

    @Test
    void rewriteOpenArraysAsPointers_strips_declarator_before_open_brackets() {
        assertEquals("uint8_t*", StructInferenceApplier.rewriteOpenArraysAsPointers("uint8_t identifier[]"));
    }
}
