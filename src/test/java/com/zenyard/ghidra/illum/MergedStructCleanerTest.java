package com.zenyard.ghidra.illum;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.JSON;
import com.zenyard.ghidra.api.generated.model.Inference;

class MergedStructCleanerTest {

    @Test
    void collectReferencedStructIdsTreatsGlobalVariableTypeStructIdsAsProtected() throws Exception {
        UUID childId = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        String payload = """
            {
              "type": "global_variable_type",
              "address": "0000000000003000",
              "type_annotation": "struct ChildStruct",
              "struct_id": "%s"
            }
            """.formatted(childId);
        Inference gvtInference = new JSON().getMapper().readValue(payload, Inference.class);

        MergedStructCleaner cleaner = new MergedStructCleaner(null, null);
        Set<UUID> referenced = cleaner.collectReferencedStructIds(
            List.of(gvtInference),
            List.of()
        );

        assertTrue(referenced.contains(childId));
    }
}
