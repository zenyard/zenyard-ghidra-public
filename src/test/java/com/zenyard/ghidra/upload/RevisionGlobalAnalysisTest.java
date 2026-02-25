package com.zenyard.ghidra.upload;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.upload.QueueRevisionsTask.Revision;

/**
 * Validates that only the last revision in a queued batch carries
 * {@code performGlobalAnalysis=true}, matching IDA behavior from PR&nbsp;#82.
 */
class RevisionGlobalAnalysisTest {

    private static Revision dummyRevision(boolean isInitialAnalysis) {
        return new Revision(Collections.emptyList(), Collections.emptyList(), isInitialAnalysis);
    }

    private static List<Revision> markLastRevisionForGlobalAnalysis(List<Revision> revisions) {
        if (!revisions.isEmpty()) {
            int lastIdx = revisions.size() - 1;
            revisions.set(lastIdx, revisions.get(lastIdx).withPerformGlobalAnalysis(true));
        }
        return revisions;
    }

    @Test
    void singleRevisionHasPerformGlobalAnalysis() {
        List<Revision> revisions = new ArrayList<>();
        revisions.add(dummyRevision(true));

        markLastRevisionForGlobalAnalysis(revisions);

        assertTrue(revisions.get(0).isPerformGlobalAnalysis());
    }

    @Test
    void multipleRevisionsOnlyLastHasPerformGlobalAnalysis() {
        List<Revision> revisions = new ArrayList<>();
        revisions.add(dummyRevision(true));
        revisions.add(dummyRevision(true));
        revisions.add(dummyRevision(true));

        markLastRevisionForGlobalAnalysis(revisions);

        for (int i = 0; i < revisions.size() - 1; i++) {
            assertFalse(revisions.get(i).isPerformGlobalAnalysis(),
                    "revision " + i + " should not request global analysis");
        }
        assertTrue(revisions.get(revisions.size() - 1).isPerformGlobalAnalysis());
    }

    @Test
    void emptyListDoesNotThrow() {
        List<Revision> revisions = new ArrayList<>();
        markLastRevisionForGlobalAnalysis(revisions);
        assertTrue(revisions.isEmpty());
    }

    @Test
    void withPerformGlobalAnalysisPreservesOtherFields() {
        Revision original = new Revision(Collections.emptyList(), Collections.emptyList(), true);
        Revision updated = original.withPerformGlobalAnalysis(true);

        assertTrue(updated.isPerformGlobalAnalysis());
        assertTrue(updated.isInitialAnalysis());
        assertTrue(updated.getObjects().isEmpty());
        assertTrue(updated.getQueuedObjects().isEmpty());
    }

    @Test
    void defaultRevisionHasPerformGlobalAnalysisFalse() {
        Revision revision = dummyRevision(false);
        assertFalse(revision.isPerformGlobalAnalysis());
    }
}
