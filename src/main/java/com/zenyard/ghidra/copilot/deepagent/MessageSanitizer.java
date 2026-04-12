package com.zenyard.ghidra.copilot.deepagent;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.ToolExecutionResultMessage;
import dev.langchain4j.data.message.UserMessage;

/**
 * Shared message sanitization utilities for PlanNode and ResponseNode.
 * Handles tool-message patching, sanitization, and reflection-based extraction.
 */
public final class MessageSanitizer {

    private MessageSanitizer() {}

    /**
     * Result of message sanitization.
     */
    public static final class SanitizeResult {
        private final List<ChatMessage> messages;

        public SanitizeResult(List<ChatMessage> messages) {
            this.messages = messages;
        }

        public List<ChatMessage> messages() {
            return messages;
        }
    }

    /**
     * Patch dangling tool calls by inserting synthetic ToolExecutionResultMessage
     * for any AiMessage tool request that has no corresponding result in the history.
     */
    public static List<ChatMessage> patchDanglingToolCalls(List<ChatMessage> input) {
        if (input == null || input.isEmpty()) {
            return List.of();
        }
        List<ChatMessage> output = new ArrayList<>(input.size());
        Set<String> toolResultIds = new HashSet<>();
        for (ChatMessage message : input) {
            if (message instanceof ToolExecutionResultMessage toolResult) {
                if (toolResult.id() != null) {
                    toolResultIds.add(toolResult.id());
                }
            }
        }
        for (ChatMessage message : input) {
            output.add(message);
            if (message instanceof AiMessage aiMessage && aiMessage.toolExecutionRequests() != null) {
                aiMessage.toolExecutionRequests().forEach(request -> {
                    String id = request.id();
                    if (id == null || toolResultIds.contains(id)) {
                        return;
                    }
                    String toolName = request.name() != null ? request.name() : "unknown";
                    String text = "Tool call " + toolName + " with id " + id
                        + " was cancelled - another message came in before it could be completed.";
                    output.add(new ToolExecutionResultMessage(id, toolName, text));
                    toolResultIds.add(id);
                });
            }
        }
        return output;
    }

    /**
     * Sanitize messages by converting tool call/result messages into plain UserMessages.
     * When sanitization is disabled, returns input unchanged.
     */
    public static SanitizeResult sanitizeMessages(List<ChatMessage> input, boolean sanitizeEnabled) {
        if (input == null || input.isEmpty()) {
            return new SanitizeResult(List.of());
        }
        if (!sanitizeEnabled) {
            return new SanitizeResult(new ArrayList<>(input));
        }
        List<ChatMessage> output = new ArrayList<>(input.size());
        for (ChatMessage message : input) {
            if (message == null) {
                continue;
            }
            String type = message.type().name();
            String toolCallSummary = extractToolCallSummaryText(message);
            if (toolCallSummary != null) {
                output.add(UserMessage.from("Tool calls: " + toolCallSummary));
                continue;
            }
            if ("TOOL_EXECUTION_RESULT".equals(type) || "TOOL".equals(type)) {
                String toolName = extractToolName(message);
                String toolId = extractToolExecutionId(message);
                String content = extractToolResultText(message);
                String header = "Tool result";
                if (!toolName.isEmpty()) {
                    header += " (" + toolName + ")";
                } else if (!toolId.isEmpty()) {
                    header += " (id=" + toolId + ")";
                }
                output.add(UserMessage.from(header + ":\n" + content));
            } else {
                output.add(message);
            }
        }
        return new SanitizeResult(output);
    }

    /**
     * Extract text content from a tool execution result message using reflection.
     */
    public static String extractToolResultText(ChatMessage message) {
        Object value = tryInvoke(message, "text");
        if (value == null) {
            value = tryInvoke(message, "result");
        }
        if (value == null) {
            value = tryInvoke(message, "content");
        }
        String text = value != null ? String.valueOf(value) : "";
        String extractedContent = extractJsonField(text, "content");
        return extractedContent.isBlank() ? text : extractedContent;
    }

    /**
     * Extract tool name from a message using reflection.
     */
    public static String extractToolName(ChatMessage message) {
        Object value = tryInvoke(message, "toolName");
        if (value == null) {
            value = tryInvoke(message, "name");
        }
        return value != null ? String.valueOf(value) : "";
    }

    /**
     * Extract tool execution ID from a message using reflection.
     */
    public static String extractToolExecutionId(ChatMessage message) {
        Object value = tryInvoke(message, "toolExecutionId");
        if (value == null) {
            value = tryInvoke(message, "id");
        }
        return value != null ? String.valueOf(value) : "";
    }

    /**
     * Extract a JSON string field value using simple parsing (no library dependency).
     */
    public static String extractJsonField(String json, String fieldName) {
        if (json == null || json.isBlank() || fieldName == null || fieldName.isBlank()) {
            return "";
        }
        String token = "\"" + fieldName + "\"";
        int start = json.indexOf(token);
        if (start < 0) {
            return "";
        }
        int colon = json.indexOf(":", start + token.length());
        if (colon < 0) {
            return "";
        }
        int firstQuote = json.indexOf("\"", colon + 1);
        if (firstQuote < 0) {
            return "";
        }
        StringBuilder value = new StringBuilder();
        boolean escaped = false;
        for (int i = firstQuote + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaped) {
                switch (c) {
                    case 'n' -> value.append('\n');
                    case 'r' -> value.append('\r');
                    case 't' -> value.append('\t');
                    case '"' -> value.append('"');
                    case '\\' -> value.append('\\');
                    default -> value.append(c);
                }
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') {
                break;
            }
            value.append(c);
        }
        return value.toString();
    }

    /**
     * Reflectively invoke a no-arg method on a ChatMessage.
     */
    static Object tryInvoke(ChatMessage message, String methodName) {
        try {
            java.lang.reflect.Method method = message.getClass().getMethod(methodName);
            return method.invoke(message);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Reflectively invoke any of the given method names on an arbitrary target.
     */
    static Object tryInvokeAny(Object target, String... methodNames) {
        if (target == null) {
            return null;
        }
        for (String methodName : methodNames) {
            try {
                java.lang.reflect.Method method = target.getClass().getMethod(methodName);
                Object result = method.invoke(target);
                if (result != null) {
                    return result;
                }
            } catch (Exception e) {
                continue;
            }
        }
        return null;
    }

    /**
     * Extract a comma-separated summary of tool call names from an AiMessage,
     * or null if the message has no tool execution requests.
     */
    private static String extractToolCallSummaryText(ChatMessage message) {
        if (message == null) {
            return null;
        }
        try {
            java.lang.reflect.Method method = message.getClass().getMethod("toolExecutionRequests");
            Object result = method.invoke(message);
            if (result instanceof List<?> requests) {
                if (requests.isEmpty()) {
                    return null;
                }
                String names = requests.stream()
                    .map(req -> tryInvokeAny(req, "name", "toolName"))
                    .map(val -> val != null ? String.valueOf(val) : "")
                    .filter(val -> !val.isBlank())
                    .collect(Collectors.joining(", "));
                return names.isBlank() ? "unknown" : names;
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }
}
