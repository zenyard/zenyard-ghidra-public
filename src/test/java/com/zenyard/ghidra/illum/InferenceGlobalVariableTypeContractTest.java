package com.zenyard.ghidra.illum;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.JSON;
import com.zenyard.ghidra.api.generated.model.GlobalVariableType;
import com.zenyard.ghidra.api.generated.model.Inference;

class InferenceGlobalVariableTypeContractTest {

    @Test
    void inferenceUnionDeserializesGlobalVariableTypePayload() throws Exception {
        UUID structId = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        String payload = """
            {
              "type": "global_variable_type",
              "address": "0000000000003000",
              "type_annotation": "struct AppConfig*",
              "struct_id": "%s"
            }
            """.formatted(structId);

        Inference inference = new JSON().getMapper().readValue(payload, Inference.class);

        GlobalVariableType actual = assertInstanceOf(GlobalVariableType.class, inference.getActualInstance());
        assertEquals("0000000000003000", actual.getAddress());
        assertEquals("struct AppConfig*", actual.getTypeAnnotation());
        assertEquals(structId, actual.getStructId());
    }
}
