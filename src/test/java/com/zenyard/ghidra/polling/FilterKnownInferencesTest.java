package com.zenyard.ghidra.polling;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.model.Inference;
import com.zenyard.ghidra.api.generated.model.MaybeUnknownInference;

/**
 * Verifies that {@link DownloadInferencesTask#filterKnownInferences} correctly
 * separates known {@link Inference} instances from unknown variants and invokes
 * the warning callback for each unrecognised entry.
 */
class FilterKnownInferencesTest {

    @Test
    void returnsKnownInferenceAndSkipsUnknown() {
        Inference known = new Inference();
        MaybeUnknownInference knownWrapper = new MaybeUnknownInference(known);
        MaybeUnknownInference unknownWrapper = new MaybeUnknownInference(new Object());

        List<Object> warnings = new ArrayList<>();
        List<Inference> result = DownloadInferencesTask.filterKnownInferences(
            Arrays.asList(knownWrapper, unknownWrapper), warnings::add);

        assertEquals(List.of(known), result);
        assertEquals(1, warnings.size());
    }

    @Test
    void returnsAllWhenAllKnown() {
        Inference a = new Inference();
        Inference b = new Inference();

        List<Object> warnings = new ArrayList<>();
        List<Inference> result = DownloadInferencesTask.filterKnownInferences(
            Arrays.asList(new MaybeUnknownInference(a), new MaybeUnknownInference(b)),
            warnings::add);

        assertEquals(List.of(a, b), result);
        assertTrue(warnings.isEmpty());
    }

    @Test
    void returnsEmptyAndWarnsWhenAllUnknown() {
        MaybeUnknownInference u1 = new MaybeUnknownInference(new Object());
        MaybeUnknownInference u2 = new MaybeUnknownInference(new Object());

        List<Object> warnings = new ArrayList<>();
        List<Inference> result = DownloadInferencesTask.filterKnownInferences(
            Arrays.asList(u1, u2), warnings::add);

        assertTrue(result.isEmpty());
        assertEquals(2, warnings.size());
    }

    @Test
    void skipsNullEntries() {
        Inference known = new Inference();
        List<MaybeUnknownInference> raw = new ArrayList<>();
        raw.add(null);
        raw.add(new MaybeUnknownInference(known));
        raw.add(null);

        List<Object> warnings = new ArrayList<>();
        List<Inference> result = DownloadInferencesTask.filterKnownInferences(raw, warnings::add);

        assertEquals(List.of(known), result);
        assertTrue(warnings.isEmpty());
    }

    @Test
    void returnsEmptyForEmptyInput() {
        List<Object> warnings = new ArrayList<>();
        List<Inference> result = DownloadInferencesTask.filterKnownInferences(
            Collections.emptyList(), warnings::add);

        assertTrue(result.isEmpty());
        assertTrue(warnings.isEmpty());
    }

    @Test
    void warningCallbackReceivesUnknownInstance() {
        Object unknownPayload = "some-future-type";
        MaybeUnknownInference unknownWrapper = new MaybeUnknownInference(unknownPayload);

        List<Object> warnings = new ArrayList<>();
        DownloadInferencesTask.filterKnownInferences(
            Collections.singletonList(unknownWrapper), warnings::add);

        assertEquals(1, warnings.size());
        assertEquals(unknownPayload, warnings.get(0));
    }
}
