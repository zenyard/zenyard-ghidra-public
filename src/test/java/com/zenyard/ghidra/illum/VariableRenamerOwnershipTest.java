package com.zenyard.ghidra.illum;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.storage.InferenceStorage.AppliedVariableRenameRecord;
import com.zenyard.ghidra.storage.InferenceStorage.VariableStorageIdentity;

class VariableRenamerOwnershipTest {

    @Test
    void resolvesPersistedIdentityUsingNormalizedOriginalName() {
        VariableStorageIdentity expected = new VariableStorageIdentity(
            "stack",
            "Stack[-0x58]",
            64
        );

        VariableStorageIdentity actual = VariableRenamer.resolvePersistedIdentity(
            "acStack_58 [64]",
            Map.of("acStack_58", expected)
        );

        assertEquals(expected.asKey(), actual.asKey());
    }

    @Test
    void findsAlternateRenameTargetForConflictingOwnerIdentity() {
        VariableStorageIdentity conflictingOwner = new VariableStorageIdentity(
            "register",
            "register:x0",
            8
        );
        VariableStorageIdentity expectedOwner = new VariableStorageIdentity(
            "register",
            "register:x1",
            8
        );

        String alternate = VariableRenamer.findAlternateRenameTarget(
            conflictingOwner,
            "container_ptr",
            Map.of(
                "pvVar4",
                new AppliedVariableRenameRecord("container_ptr", expectedOwner),
                "iVar1",
                new AppliedVariableRenameRecord("temp_result", conflictingOwner)
            )
        );

        assertEquals("temp_result", alternate);
    }

    @Test
    void doesNotSuggestAlternateWhenOnlyConflictingTargetExists() {
        VariableStorageIdentity conflictingOwner = new VariableStorageIdentity(
            "register",
            "register:x0",
            8
        );

        String alternate = VariableRenamer.findAlternateRenameTarget(
            conflictingOwner,
            "container_ptr",
            Map.of(
                "pvVar4",
                new AppliedVariableRenameRecord("container_ptr", conflictingOwner)
            )
        );

        assertNull(alternate);
    }

    @Test
    void reclaimsOnlyWhenAlternateTargetAndDistinctIdentityExist() {
        VariableStorageIdentity expectedOwner = new VariableStorageIdentity(
            "register",
            "register:x1",
            8
        );
        VariableStorageIdentity conflictingOwner = new VariableStorageIdentity(
            "register",
            "register:x0",
            8
        );

        assertTrue(VariableRenamer.shouldReclaimConflictingTarget(
            expectedOwner,
            conflictingOwner,
            "temp_result"
        ));
        assertFalse(VariableRenamer.shouldReclaimConflictingTarget(
            expectedOwner,
            conflictingOwner,
            null
        ));
        assertFalse(VariableRenamer.shouldReclaimConflictingTarget(
            expectedOwner,
            expectedOwner,
            "temp_result"
        ));
    }
}
