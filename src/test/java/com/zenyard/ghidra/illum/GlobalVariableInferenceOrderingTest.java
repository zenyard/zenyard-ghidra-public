package com.zenyard.ghidra.illum;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.JSON;
import com.zenyard.ghidra.api.generated.model.GlobalVariableType;
import com.zenyard.ghidra.api.generated.model.Inference;

class GlobalVariableInferenceOrderingTest {

    @Test
    void extractGlobalVariableType_readsTypedInstance() throws Exception {
        UUID sid = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        String payload = """
            {
              "type": "global_variable_type",
              "address": "0000000000003000",
              "type_annotation": "struct Foo",
              "struct_id": "%s"
            }
            """.formatted(sid);
        Inference inference = new JSON().getMapper().readValue(payload, Inference.class);
        GlobalVariableType gvt = GlobalVariableInferenceOrdering.extractGlobalVariableType(inference);
        assertNotNull(gvt);
        assertEquals("struct Foo", gvt.getTypeAnnotation());
        assertEquals(sid, gvt.getStructId());
    }

    @Test
    void extractGlobalVariableType_readsMapShapedPayload() throws Exception {
        String payload = """
            {
              "type": "global_variable_type",
              "address": "0000000000004000",
              "type_annotation": "struct Bar",
              "struct_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
            }
            """;
        Inference inference = new JSON().getMapper().readValue(payload, Inference.class);
        GlobalVariableType gvt = GlobalVariableInferenceOrdering.extractGlobalVariableType(inference);
        assertNotNull(gvt);
        assertEquals("struct Bar", gvt.getTypeAnnotation());
    }
}
