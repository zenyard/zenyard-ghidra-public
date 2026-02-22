package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.bsc.langgraph4j.langchain4j.tool.LC4jToolResponseBuilder;

import com.zenyard.ghidra.copilot.deepagent.CopilotDeepState;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.invocation.InvocationParameters;

/**
 * Planning tool to update the TODO list in agent state.
 */
public class WriteTodosTool {

    @Tool(
        name = "write_todos",
        value = "Update the agent TODO state. Input `todos` accepts either strings or objects like {content, status}. Valid status values: pending, in_progress, completed, failed."
    )
    public String writeTodos(
            @P("List of TODO items. Each item can be a string (content only) or an object `{content, status}`.") List<Object> todos,
            InvocationParameters context) {
        List<String> sanitized = new ArrayList<>();
        List<String> completed = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        String activeTodo = "";

        if (todos != null) {
            for (Object item : todos) {
                if (item == null) {
                    continue;
                }
                if (item instanceof String text) {
                    String trimmed = text.trim();
                    if (!trimmed.isEmpty()) {
                        sanitized.add(trimmed);
                    }
                    continue;
                }
                if (item instanceof Map<?, ?> map) {
                    Object rawContent = map.get("content");
                    if (rawContent == null) {
                        continue;
                    }
                    String content = String.valueOf(rawContent).trim();
                    if (content.isEmpty()) {
                        continue;
                    }
                    sanitized.add(content);

                    Object rawStatus = map.get("status");
                    String status = rawStatus == null ? "pending" : String.valueOf(rawStatus).trim().toLowerCase();
                    if ("completed".equals(status)) {
                        completed.add(content);
                    } else if ("failed".equals(status)) {
                        failed.add(content);
                    } else if ("in_progress".equals(status) && activeTodo.isEmpty()) {
                        activeTodo = content;
                    }
                }
            }
        }

        if (isUnchangedState(sanitized, activeTodo, completed, failed, context)) {
            return LC4jToolResponseBuilder.of(context)
                .buildAndReturn("TODOs unchanged.");
        }

        return LC4jToolResponseBuilder.of(context)
            .update(Map.of(
                CopilotDeepState.TODOS, sanitized,
                CopilotDeepState.ACTIVE_TODO, activeTodo,
                CopilotDeepState.COMPLETED_TODOS, completed,
                CopilotDeepState.FAILED_TODOS, failed
            ))
            .buildAndReturn("Updated TODOs (" + sanitized.size() + " items).");
    }

    private boolean isUnchangedState(
            List<String> todos,
            String activeTodo,
            List<String> completed,
            List<String> failed,
            InvocationParameters context) {
        if (context == null) {
            return false;
        }

        List<String> currentTodos = normalizeStringList(context.get(CopilotDeepState.TODOS));
        List<String> currentCompleted = normalizeStringList(context.get(CopilotDeepState.COMPLETED_TODOS));
        List<String> currentFailed = normalizeStringList(context.get(CopilotDeepState.FAILED_TODOS));
        String currentActive = normalizeActiveTodo(context.get(CopilotDeepState.ACTIVE_TODO));
        String nextActive = normalizeActiveTodo(activeTodo);

        return currentTodos.equals(normalizeStringList(todos))
            && currentCompleted.equals(normalizeStringList(completed))
            && currentFailed.equals(normalizeStringList(failed))
            && java.util.Objects.equals(currentActive, nextActive);
    }

    private List<String> normalizeStringList(Object value) {
        List<String> normalized = new ArrayList<>();
        if (!(value instanceof List<?> rawList)) {
            return normalized;
        }
        java.util.LinkedHashSet<String> seen = new java.util.LinkedHashSet<>();
        for (Object item : rawList) {
            if (item == null) {
                continue;
            }
            String text = String.valueOf(item).trim();
            if (!text.isEmpty()) {
                seen.add(text);
            }
        }
        normalized.addAll(seen);
        return normalized;
    }

    private String normalizeActiveTodo(Object value) {
        if (value == null) {
            return "";
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? "" : text;
    }
}
