package com.zenyard.ghidra.illum;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class InferenceApplierOverviewNormalizationTest {

    @Test
    void rewritesResolvableFunToken() {
        String input = "Calls FUN_1000 before returning.";
        String normalized = InferenceApplier.normalizeOverviewFunctionNames(
            input,
            token -> "1000".equalsIgnoreCase(token) ? "do_work" : null
        );
        assertEquals("Calls do_work before returning.", normalized);
    }

    @Test
    void leavesUnresolvableFunTokenUnchanged() {
        String input = "Delegates into FUN_deadbeef.";
        String normalized = InferenceApplier.normalizeOverviewFunctionNames(input, token -> null);
        assertEquals("Delegates into FUN_deadbeef.", normalized);
    }

    @Test
    void leavesNonFunTextUntouched() {
        String input = "No synthetic function references here.";
        String normalized = InferenceApplier.normalizeOverviewFunctionNames(input, token -> "ignored");
        assertEquals(input, normalized);
    }

    @Test
    void treatsNormalizedStoredOverviewAsInferredComment() {
        String plateComment = "Calls perform_init.";
        String storedDescription = "Calls FUN_401000.";
        boolean inferred = InferenceApplier.isStoredOverviewEquivalentForComment(
            plateComment,
            storedDescription,
            text -> InferenceApplier.normalizeOverviewFunctionNames(
                text,
                token -> "401000".equalsIgnoreCase(token) ? "perform_init" : null
            )
        );
        assertTrue(inferred);
    }

    @Test
    void keepsUserEditedCommentProtected() {
        String plateComment = "User edited explanation";
        String storedDescription = "Calls FUN_401000.";
        boolean inferred = InferenceApplier.isStoredOverviewEquivalentForComment(
            plateComment,
            storedDescription,
            text -> InferenceApplier.normalizeOverviewFunctionNames(
                text,
                token -> "401000".equalsIgnoreCase(token) ? "perform_init" : null
            )
        );
        assertFalse(inferred);
    }
}
