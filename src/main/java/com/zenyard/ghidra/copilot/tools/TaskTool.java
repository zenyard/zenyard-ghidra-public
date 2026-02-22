package com.zenyard.ghidra.copilot.tools;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bsc.langgraph4j.langchain4j.tool.LC4jToolResponseBuilder;

import com.zenyard.ghidra.copilot.CopilotPrompts;
import com.zenyard.ghidra.copilot.deepagent.CopilotDeepState;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.invocation.InvocationParameters;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;

/**
 * Task tool to spawn short-lived subagents for isolated work.
 */
public class TaskTool {
    private final ChatModel chatModel;
    private final String systemPrompt;

    public TaskTool(ChatModel chatModel, String systemPrompt) {
        this.chatModel = chatModel;
        this.systemPrompt = systemPrompt;
    }

    @Tool(
        name = "task",
        value = CopilotPrompts.TASK_TOOL_DESCRIPTION
    )
    public String task(
            @P("Task description to delegate to a short-lived subagent.") String description,
            @P("Subagent type. Allowed values: critic, toolrunner, researcher, explore, general-purpose.") String subagentType,
            InvocationParameters context) {
        String role = normalizeRole(subagentType);
        if (role == null) {
            return "Unknown subagent type: " + subagentType;
        }
        List<ChatMessage> messages = List.of(
            SystemMessage.from(systemPrompt + "\n\n" + CopilotPrompts.TASK_SYSTEM_PROMPT + "\n\n" + rolePrompt(role)),
            UserMessage.from(description != null ? description : "")
        );
        ChatRequest request = ChatRequest.builder()
            .messages(messages)
            .build();
        ChatResponse response = chatModel.chat(request);
        AiMessage aiMessage = response.aiMessage();
        String text = aiMessage != null && aiMessage.text() != null ? aiMessage.text() : "";

        int nextCount = readSubagentCount(context) + 1;
        Map<String, String> artifacts = new HashMap<>();
        artifacts.put(roleArtifactPath(role), text);

        return LC4jToolResponseBuilder.of(context)
            .update(Map.of(
                CopilotDeepState.SUBAGENT_COUNT, nextCount,
                CopilotDeepState.ARTIFACTS, artifacts,
                CopilotDeepState.FILES, artifacts))
            .buildAndReturn(text.isBlank() ? "Task completed." : text);
    }

    private String normalizeRole(String subagentType) {
        if (subagentType == null) {
            return "general-purpose";
        }
        String normalized = subagentType.trim().toLowerCase();
        return switch (normalized) {
            case "critic", "toolrunner", "researcher", "explore", "general-purpose" -> normalized;
            default -> null;
        };
    }

    private String rolePrompt(String role) {
        return CopilotPrompts.subagentRolePrompt(role);
    }

    private String roleArtifactPath(String role) {
        return switch (role) {
            case "researcher" -> "research/notes.md";
            case "explore" -> "explore/notes.md";
            case "critic", "toolrunner", "general-purpose" -> "subagents/" + role + ".md";
            default -> "subagents/unknown.md";
        };
    }

    private int readSubagentCount(InvocationParameters context) {
        if (context == null) {
            return 0;
        }
        Object value = context.get(CopilotDeepState.SUBAGENT_COUNT);
        if (value instanceof Number number) {
            return number.intValue();
        }
        return 0;
    }
}
