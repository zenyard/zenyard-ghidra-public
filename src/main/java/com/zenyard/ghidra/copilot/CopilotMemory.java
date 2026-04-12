package com.zenyard.ghidra.copilot;

import java.util.List;

import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.memory.chat.TokenWindowChatMemory;
import dev.langchain4j.model.TokenCountEstimator;

/**
 * Wrapper for Copilot chat memory management.
 * Uses TokenWindowChatMemory for automatic token-based memory management.
 * 
 * Mirrors IDA's InMemorySaver pattern but with token-based limits.
 */
public class CopilotMemory {
    
    private static final int MAX_TOKENS = 150_000; // Token threshold (matches IDA)
    private static final int SUMMARIZATION_TRIGGER = 140_000; // Trigger summarization at 140k tokens
    
    private final ChatMemory chatMemory;
    private final String threadId;
    private final TokenCountEstimator tokenCountEstimator;
    
    /**
     * Create CopilotMemory with a TokenCountEstimator.
     * 
     * @param threadId The thread ID for conversation isolation
     * @param tokenCountEstimator The token count estimator to use (required)
     */
    public CopilotMemory(String threadId, TokenCountEstimator tokenCountEstimator) {
        this.threadId = threadId;
        this.tokenCountEstimator = tokenCountEstimator;
        
        // Use TokenWindowChatMemory for automatic token-based memory management
        // This automatically evicts old messages when token limit is reached
        this.chatMemory = TokenWindowChatMemory.builder()
            .id(threadId)
            .maxTokens(MAX_TOKENS, tokenCountEstimator)
            .build();
    }
    
    /**
     * Get the chat memory instance.
     */
    public ChatMemory getChatMemory() {
        return chatMemory;
    }
    
    /**
     * Get the thread ID for this conversation.
     */
    public String getThreadId() {
        return threadId;
    }
    
    /**
     * Clear the conversation history.
     */
    public void clear() {
        chatMemory.clear();
    }
    
    /**
     * Check if we need to trigger summarization based on token count.
     * Returns true when approaching the token limit (at SUMMARIZATION_TRIGGER).
     */
    public boolean shouldSummarize() {
        return getCurrentTokenCount() >= SUMMARIZATION_TRIGGER;
    }
    
    /**
     * Get the TokenCountEstimator used by this memory.
     */
    public TokenCountEstimator getTokenCountEstimator() {
        return tokenCountEstimator;
    }
    
    /**
     * Get current token count in the memory.
     * Counts tokens for all messages currently in memory.
     */
    public int getCurrentTokenCount() {
        List<ChatMessage> messages = chatMemory.messages();
        if (tokenCountEstimator != null) {
            return tokenCountEstimator.estimateTokenCountInMessages(messages);
        }
        // Fallback: estimate tokens (rough: ~4 chars per token)
        return countTokensEstimate(messages);
    }
    
    /**
     * Estimate tokens in a list of messages (fallback when tokenCountEstimator not available).
     */
    private int countTokensEstimate(List<ChatMessage> messages) {
        int totalTokens = 0;
        for (ChatMessage message : messages) {
            String text = extractTextFromMessage(message);
            if (text != null && !text.isEmpty()) {
                totalTokens += text.length() / 4; // Rough estimate
            }
        }
        return totalTokens;
    }
    
    /**
     * Extract text from a ChatMessage, handling different message types.
     */
    private String extractTextFromMessage(ChatMessage message) {
        if (message instanceof dev.langchain4j.data.message.UserMessage) {
            return ((dev.langchain4j.data.message.UserMessage) message).singleText();
        } else if (message instanceof dev.langchain4j.data.message.AiMessage) {
            return ((dev.langchain4j.data.message.AiMessage) message).text();
        } else if (message instanceof dev.langchain4j.data.message.SystemMessage) {
            return ((dev.langchain4j.data.message.SystemMessage) message).text();
        } else {
            // Fallback: use toString() for other message types
            return message.toString();
        }
    }
    
    /**
     * Get all messages from the memory.
     */
    public List<ChatMessage> getMessages() {
        return chatMemory.messages();
    }
    
    /**
     * Replace all messages in memory with new messages.
     * Used for summarization: replace old messages with a summary message.
     */
    public void replaceMessages(List<ChatMessage> newMessages) {
        // Clear current messages
        chatMemory.clear();
        
        // Add new messages
        for (ChatMessage message : newMessages) {
            chatMemory.add(message);
        }
    }
    
    /**
     * Get the SUMMARIZATION_TRIGGER constant.
     */
    public static int getSummarizationTrigger() {
        return SUMMARIZATION_TRIGGER;
    }

    public static int getMaxTokens() {
        return MAX_TOKENS;
    }
}

