package com.zenyard.ghidra.copilot.deepagent;

import java.util.ArrayList;
import java.util.List;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.memory.ChatMemory;

/**
 * Adapter to expose ChatMemory to DeepAgent flows.
 */
public class DeepAgentMemoryAdapter {
    private final ChatMemory chatMemory;

    public DeepAgentMemoryAdapter(ChatMemory chatMemory) {
        this.chatMemory = chatMemory;
    }

    public List<ChatMessage> getHistory() {
        if (chatMemory == null) {
            return List.of();
        }
        return new ArrayList<>(chatMemory.messages());
    }

    public void recordTurn(UserMessage userMessage, AiMessage aiMessage) {
        if (chatMemory == null) {
            return;
        }
        if (userMessage != null && !isBlank(userMessage.singleText())) {
            chatMemory.add(userMessage);
        }
        if (aiMessage != null && !isBlank(aiMessage.text())) {
            chatMemory.add(aiMessage);
        }
    }

    public void clear() {
        if (chatMemory != null) {
            chatMemory.clear();
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

}
