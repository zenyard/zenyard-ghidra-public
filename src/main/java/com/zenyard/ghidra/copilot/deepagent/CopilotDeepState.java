package com.zenyard.ghidra.copilot.deepagent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.bsc.langgraph4j.prebuilt.MessagesState;
import org.bsc.langgraph4j.state.Channel;
import org.bsc.langgraph4j.state.Channels;

import dev.langchain4j.data.message.ChatMessage;

/**
 * Deep Agent state for Copilot.
 * Extends MessagesState with explicit planning, artifacts, and execution metadata.
 */
public class CopilotDeepState extends MessagesState<ChatMessage> {

    public static final String MESSAGES = MessagesState.MESSAGES_STATE;
    public static final String TODOS = "todos";
    public static final String ACTIVE_TODO = "active_todo";
    public static final String ARTIFACTS = "artifacts";
    public static final String FILES = "files";
    public static final String FINAL_RESPONSE = "final_response";
    public static final String TOOL_EVENTS = "tool_events";
    public static final String SUBAGENT_COUNT = "subagent_count";
    public static final String SKILLS_PROMPT = "skills_prompt";
    public static final String JUMP_TO = "jump_to";
    public static final String RETURN_DIRECT = "return_direct";
    public static final String COMPLETED_TODOS = "completed_todos";
    public static final String FAILED_TODOS = "failed_todos";
    public static final String LAST_TOOL_BATCH_SIGNATURE = "last_tool_batch_signature";
    public static final String SAME_TOOL_BATCH_COUNT = "same_tool_batch_count";
    public static final String LOOP_GUARD_MESSAGE = "loop_guard_message";
    public static final String LOOP_GUARD_PIVOT_COUNT = "loop_guard_pivot_count";

    public static final Map<String, Channel<?>> SCHEMA = buildSchema();

    private static Map<String, Channel<?>> buildSchema() {
        Map<String, Channel<?>> schema = new HashMap<>(MessagesState.SCHEMA);
        SharedStateSchema.addCommonFields(schema);
        schema.put(ACTIVE_TODO, Channels.base(SharedStateSchema.replaceReducer(), () -> ""));
        schema.put(FINAL_RESPONSE, Channels.base(SharedStateSchema.replaceReducer(), () -> ""));
        schema.put(TOOL_EVENTS, Channels.base(SharedStateSchema.replaceReducer(), ArrayList::new));
        schema.put(SUBAGENT_COUNT, Channels.base(SharedStateSchema.replaceReducer(), () -> 0));
        schema.put(SKILLS_PROMPT, Channels.base(SharedStateSchema.replaceReducer(), () -> ""));
        schema.put(JUMP_TO, Channels.base(SharedStateSchema.replaceReducer(), () -> ""));
        schema.put(RETURN_DIRECT, Channels.base(SharedStateSchema.replaceReducer(), () -> Boolean.FALSE));
        schema.put(COMPLETED_TODOS, Channels.base(SharedStateSchema.replaceReducer(), ArrayList::new));
        schema.put(FAILED_TODOS, Channels.base(SharedStateSchema.replaceReducer(), ArrayList::new));
        schema.put(LAST_TOOL_BATCH_SIGNATURE, Channels.base(SharedStateSchema.replaceReducer(), () -> ""));
        schema.put(SAME_TOOL_BATCH_COUNT, Channels.base(SharedStateSchema.replaceReducer(), () -> 0));
        schema.put(LOOP_GUARD_MESSAGE, Channels.base(SharedStateSchema.replaceReducer(), () -> ""));
        schema.put(LOOP_GUARD_PIVOT_COUNT, Channels.base(SharedStateSchema.replaceReducer(), () -> 0));
        return Map.copyOf(schema);
    }

    public CopilotDeepState(Map<String, Object> initData) {
        super(initData);
    }

    public List<String> todos() {
        return this.<List<String>>value(TODOS).orElseGet(ArrayList::new);
    }

    public Optional<String> activeTodo() {
        return value(ACTIVE_TODO)
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .filter(todo -> !todo.isBlank());
    }

    public Map<String, String> artifacts() {
        return this.<Map<String, String>>value(ARTIFACTS).orElseGet(HashMap::new);
    }

    public Optional<String> finalResponse() {
        return value(FINAL_RESPONSE);
    }

    public List<String> toolEvents() {
        return this.<List<String>>value(TOOL_EVENTS).orElseGet(ArrayList::new);
    }

    public int subAgentCount() {
        return this.<Integer>value(SUBAGENT_COUNT).orElse(0);
    }

    public Optional<String> skillsPrompt() {
        return value(SKILLS_PROMPT);
    }

    public Optional<String> jumpTo() {
        return value(JUMP_TO)
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .map(String::trim)
            .filter(v -> !v.isBlank());
    }

    public boolean returnDirect() {
        return this.<Boolean>value(RETURN_DIRECT).orElse(Boolean.FALSE);
    }

    public List<String> completedTodos() {
        return this.<List<String>>value(COMPLETED_TODOS).orElseGet(ArrayList::new);
    }

    public List<String> failedTodos() {
        return this.<List<String>>value(FAILED_TODOS).orElseGet(ArrayList::new);
    }

    public String lastToolBatchSignature() {
        return value(LAST_TOOL_BATCH_SIGNATURE)
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .orElse("");
    }

    public int sameToolBatchCount() {
        return this.<Integer>value(SAME_TOOL_BATCH_COUNT).orElse(0);
    }

    public Optional<String> loopGuardMessage() {
        return value(LOOP_GUARD_MESSAGE)
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .filter(s -> !s.isBlank());
    }

    public int loopGuardPivotCount() {
        return this.<Integer>value(LOOP_GUARD_PIVOT_COUNT).orElse(0);
    }
}
