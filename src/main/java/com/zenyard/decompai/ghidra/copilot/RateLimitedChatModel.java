package com.zenyard.decompai.ghidra.copilot;

import java.util.List;

import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;

/**
 * Decorator for ChatModel that applies rate limiting.
 * Wraps a ChatModel and applies rate limiting before each call.
 */
public class RateLimitedChatModel implements ChatModel {
    
    private final ChatModel delegate;
    private final CopilotRateLimiter rateLimiter;
    
    public RateLimitedChatModel(ChatModel delegate, CopilotRateLimiter rateLimiter) {
        this.delegate = delegate;
        this.rateLimiter = rateLimiter;
    }
    
    @Override
    public ChatResponse chat(ChatRequest chatRequest) {
        try {
            rateLimiter.acquire();
            return delegate.chat(chatRequest);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Rate limiter interrupted", e);
        }
    }
    
    @Override
    public String chat(String userMessage) {
        try {
            rateLimiter.acquire();
            return delegate.chat(userMessage);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Rate limiter interrupted", e);
        }
    }
    
    @Override
    public ChatResponse chat(ChatMessage... messages) {
        try {
            rateLimiter.acquire();
            return delegate.chat(messages);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Rate limiter interrupted", e);
        }
    }
    
    @Override
    public ChatResponse chat(List<ChatMessage> messages) {
        try {
            rateLimiter.acquire();
            return delegate.chat(messages);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Rate limiter interrupted", e);
        }
    }
}

