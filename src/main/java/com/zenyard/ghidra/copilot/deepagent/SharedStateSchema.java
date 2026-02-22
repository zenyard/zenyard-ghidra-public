package com.zenyard.ghidra.copilot.deepagent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.bsc.langgraph4j.state.Channel;
import org.bsc.langgraph4j.state.Channels;
import org.bsc.langgraph4j.state.Reducer;

/**
 * Shared state schema fields and reducers used by both CopilotDeepState
 * and CopilotDeepAgentState, eliminating duplication.
 */
public final class SharedStateSchema {

    private SharedStateSchema() {}

    public static final String TODOS = "todos";
    public static final String FILES = "files";
    public static final String ARTIFACTS = "artifacts";

    /**
     * Add common fields (todos, files, artifacts) to a schema map.
     */
    public static void addCommonFields(Map<String, Channel<?>> schema) {
        schema.put(TODOS, Channels.base(replaceReducer(), ArrayList::new));
        schema.put(FILES, Channels.base(mergeMapReducer(), HashMap::new));
        schema.put(ARTIFACTS, Channels.base(mergeMapReducer(), HashMap::new));
    }

    /**
     * Replace-last-write reducer.
     */
    public static <T> Reducer<T> replaceReducer() {
        return (oldValue, newValue) -> newValue;
    }

    /**
     * Merge-map reducer that combines old and new map entries.
     */
    public static <V> Reducer<Map<String, V>> mergeMapReducer() {
        return (oldValue, newValue) -> {
            Map<String, V> merged = new HashMap<>();
            if (oldValue != null) {
                merged.putAll(oldValue);
            }
            if (newValue != null) {
                merged.putAll(newValue);
            }
            return merged;
        };
    }
}
