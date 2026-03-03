package com.zenyard.ghidra.status;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe tracker for raw inference counts by type name.
 * Shared between {@link ApplyInferencesTask} (increments) and
 * {@link AnalysisProgressMonitor} (reads / resets).
 */
public class InferenceCountTracker {

    private final ConcurrentHashMap<String, AtomicInteger> counts = new ConcurrentHashMap<>();

    public void increment(String inferenceType) {
        counts.computeIfAbsent(inferenceType, k -> new AtomicInteger()).incrementAndGet();
    }

    public void reset() {
        counts.clear();
    }

    /** Return a snapshot of current counts as an unmodifiable map. */
    public Map<String, Integer> snapshot() {
        Map<String, Integer> snap = new HashMap<>();
        counts.forEach((k, v) -> snap.put(k, v.get()));
        return Collections.unmodifiableMap(snap);
    }
}
