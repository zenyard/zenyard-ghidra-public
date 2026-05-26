package com.zenyard.ghidra.illum;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import com.zenyard.ghidra.storage.InferenceStorage;

import ghidra.framework.options.Options;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

/**
 * Tests for {@link StructInferenceApplier#resolveInferenceDataType} struct_id + array annotations.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class StructInferenceApplierResolveInferenceDataTypeTest {

    private static final CategoryPath ZENYARD_STRUCTS = new CategoryPath("/zenyard/structs");
    private static final UUID STRUCT_ID = UUID.fromString("ffbc9d2b-5dba-45ed-9e7d-31d374d6ce05");

    @Mock
    private Program program;

    private ProgramBasedDataTypeManager dtm;
    private StructureDataType fooStruct;
    private InferenceStorage inferenceStorage;
    @BeforeEach
    void setUp() throws Exception {
        dtm = mock(ProgramBasedDataTypeManager.class);
        fooStruct = new StructureDataType(ZENYARD_STRUCTS, "Foo", 0, dtm);
        fooStruct.insertAtOffset(0, DWordDataType.dataType, 4, "a", null);
        when(dtm.addDataType(any(DataType.class), any(DataTypeConflictHandler.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));

        when(program.getDataTypeManager()).thenReturn(dtm);
        when(program.getDefaultPointerSize()).thenReturn(8);
        when(program.isClosed()).thenReturn(false);
        Options options = mock(Options.class);
        when(options.getString(anyString(), any())).thenReturn(null);
        when(program.getOptions(anyString())).thenReturn(options);
        when(program.startTransaction(anyString())).thenReturn(0);
        inferenceStorage = new InferenceStorage(program);

        when(dtm.getDataType(eq("/uchar"))).thenReturn(ByteDataType.dataType);
        when(dtm.getDataType(eq("/byte"))).thenReturn(ByteDataType.dataType);
        when(dtm.getDataType(eq("/char"))).thenReturn(ByteDataType.dataType);
    }

    /**
     * Resolves struct by id to a fixed DTM type (avoids persisting struct name in InferenceStorage).
     */
    private static final class TestStructInferenceApplier extends StructInferenceApplier {
        private final DataType mapped;

        TestStructInferenceApplier(InferenceStorage storage, DataType mapped) {
            super(storage);
            this.mapped = mapped;
        }

        @Override
        public DataType resolveStructTypeById(Program program, UUID structId) {
            if (STRUCT_ID.equals(structId)) {
                return mapped;
            }
            return null;
        }
    }

    @Test
    void structIdWithArrayAnnotation_yieldsArrayDataType() {
        StructInferenceApplier applier = new TestStructInferenceApplier(inferenceStorage, fooStruct);

        DataType resolved = applier.resolveInferenceDataType(
            program,
            "struct Foo[4]",
            STRUCT_ID);

        ArrayDataType array = assertInstanceOf(ArrayDataType.class, resolved);
        assertEquals(4, array.getNumElements());
        assertSame(fooStruct, array.getDataType());
        assertEquals(4 * fooStruct.getLength(), array.getLength());
    }

    @Test
    void structIdWithoutArrayAnnotation_yieldsStruct() {
        StructInferenceApplier applier = new TestStructInferenceApplier(inferenceStorage, fooStruct);

        DataType resolved = applier.resolveInferenceDataType(program, "struct Foo", STRUCT_ID);

        assertSame(fooStruct, resolved);
    }

    @Test
    void structIdWithPointerAnnotation_yieldsPointerToStruct() {
        StructInferenceApplier applier = new TestStructInferenceApplier(inferenceStorage, fooStruct);

        DataType resolved = applier.resolveInferenceDataType(program, "struct Foo*", STRUCT_ID);

        PointerDataType ptr = assertInstanceOf(PointerDataType.class, resolved);
        assertSame(fooStruct, ptr.getDataType());
    }

    @Test
    void structIdWithOpenArrayAnnotation_yieldsPointerToStruct() {
        StructInferenceApplier applier = new TestStructInferenceApplier(inferenceStorage, fooStruct);

        DataType resolved = applier.resolveInferenceDataType(program, "struct Foo[]", STRUCT_ID);

        PointerDataType ptr = assertInstanceOf(PointerDataType.class, resolved);
        assertSame(fooStruct, ptr.getDataType());
    }

    @Test
    void openArray_uint8_matches_uint8_star() {
        StructInferenceApplier applier = new StructInferenceApplier(inferenceStorage);

        DataType fromBracket = applier.resolveInferenceDataType(program, "uint8_t[]", null);
        DataType fromStar = applier.resolveInferenceDataType(program, "uint8_t*", null);

        PointerDataType p1 = assertInstanceOf(PointerDataType.class, fromBracket);
        PointerDataType p2 = assertInstanceOf(PointerDataType.class, fromStar);
        assertEquals(p2.getDataType(), p1.getDataType());
    }

    @Test
    void openArray_char_matches_char_star() {
        StructInferenceApplier applier = new StructInferenceApplier(inferenceStorage);

        DataType fromBracket = applier.resolveInferenceDataType(program, "char[]", null);
        DataType fromStar = applier.resolveInferenceDataType(program, "char*", null);

        PointerDataType p1 = assertInstanceOf(PointerDataType.class, fromBracket);
        PointerDataType p2 = assertInstanceOf(PointerDataType.class, fromStar);
        assertEquals(p2.getDataType(), p1.getDataType());
    }

    @Test
    void openArray_char_star_array_matches_char_star_star() {
        StructInferenceApplier applier = new StructInferenceApplier(inferenceStorage);

        DataType fromBracket = applier.resolveInferenceDataType(program, "char*[]", null);
        DataType fromStar = applier.resolveInferenceDataType(program, "char**", null);

        PointerDataType p1 = assertInstanceOf(PointerDataType.class, fromBracket);
        PointerDataType p2 = assertInstanceOf(PointerDataType.class, fromStar);
        assertEquals(p2.getDataType(), p1.getDataType());
    }

    @Test
    void declarator_uint8_identifier_open_array_matches_uint8_star() {
        StructInferenceApplier applier = new StructInferenceApplier(inferenceStorage);

        DataType fromDecl = applier.resolveInferenceDataType(program, "uint8_t identifier[]", null);
        DataType fromStar = applier.resolveInferenceDataType(program, "uint8_t*", null);

        PointerDataType p1 = assertInstanceOf(PointerDataType.class, fromDecl);
        PointerDataType p2 = assertInstanceOf(PointerDataType.class, fromStar);
        assertEquals(p2.getDataType(), p1.getDataType());
    }

    @Test
    void struct_id_missing_open_array_falls_back_to_pointer_resolution() {
        StructInferenceApplier applier = new StructInferenceApplier(inferenceStorage);
        UUID orphanId = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

        DataType resolved = applier.resolveInferenceDataType(program, "uint8_t[]", orphanId);

        PointerDataType ptr = assertInstanceOf(PointerDataType.class, resolved);
        assertEquals(ByteDataType.dataType, ptr.getDataType());
    }
}
