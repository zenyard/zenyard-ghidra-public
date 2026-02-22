package com.zenyard.ghidra.copilot.deepagent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.bsc.langgraph4j.agentexecutor.AgentExecutor;
import org.bsc.langgraph4j.prebuilt.MessagesState;
import org.bsc.langgraph4j.state.Channel;

/**
 * Deep Agent state for Copilot using the AgentExecutor base state.
 */
public class CopilotDeepAgentState extends AgentExecutor.State {

    public static final String MESSAGES = MessagesState.MESSAGES_STATE;
    public static final String TODOS = "todos";
    public static final String FILES = "files";
    public static final String ARTIFACTS = "artifacts";

    public static final Map<String, Channel<?>> SCHEMA = buildSchema();

    private static Map<String, Channel<?>> buildSchema() {
        Map<String, Channel<?>> schema = new HashMap<>(MessagesState.SCHEMA);
        SharedStateSchema.addCommonFields(schema);
        return Map.copyOf(schema);
    }

    public CopilotDeepAgentState(Map<String, Object> initData) {
        super(initData);
    }

    public List<ToDo> todos() {
        return this.<List<ToDo>>value(TODOS).orElseGet(ArrayList::new);
    }

    public Map<String, String> files() {
        return this.<Map<String, String>>value(FILES).orElseGet(HashMap::new);
    }

    public Map<String, String> artifacts() {
        return this.<Map<String, String>>value(ARTIFACTS).orElseGet(HashMap::new);
    }

    public Optional<String> artifact(String key) {
        return Optional.ofNullable(artifacts().get(key));
    }

    public record ToDo(String content, Status status) {
        public enum Status {
            PENDING,
            IN_PROGRESS,
            COMPLETED
        }
    }
}
