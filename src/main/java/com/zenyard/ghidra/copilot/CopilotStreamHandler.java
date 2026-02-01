package com.zenyard.ghidra.copilot;

import javax.swing.SwingUtilities;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.chat.response.StreamingChatResponseHandler;

/**
 * Streaming response handler for Copilot agent.
 * Streams tokens to the UI via CopilotViewModel.
 * 
 * Mirrors the streaming behavior from IDA's copilot_task.py.
 */
public class CopilotStreamHandler implements StreamingChatResponseHandler {
    
    private final CopilotViewModel viewModel;
    private final StringBuilder currentMessage;
    private volatile boolean cancelled;
    
    public CopilotStreamHandler(CopilotViewModel viewModel) {
        this.viewModel = viewModel;
        this.currentMessage = new StringBuilder();
        this.cancelled = false;
    }
    
    @Override
    public void onPartialResponse(String partialResponse) {
        if (cancelled) {
            return;
        }
        
        // Aggregate tokens
        synchronized (currentMessage) {
            currentMessage.append(partialResponse);
        }
        
        // Update UI on EDT
        SwingUtilities.invokeLater(() -> {
            if (!cancelled) {
                viewModel.appendToLastMessage(partialResponse);
            }
        });
    }
    
    @Override
    public void onCompleteResponse(ChatResponse completeResponse) {
        if (cancelled) {
            return;
        }
        
        // Finalize message
        SwingUtilities.invokeLater(() -> {
            viewModel.setLoading(false);
            viewModel.setThinking(false, null);
        });
    }
    
    @Override
    public void onError(Throwable error) {
        // Handle streaming errors
        SwingUtilities.invokeLater(() -> {
            viewModel.setError("Streaming error: " + error.getMessage());
            viewModel.setLoading(false);
            viewModel.setThinking(false, null);
        });
    }
    
    /**
     * Legacy method for compatibility - maps to onPartialResponse
     */
    public void onNext(String token) {
        onPartialResponse(token);
    }
    
    /**
     * Legacy method for compatibility - maps to onCompleteResponse
     */
    public void onComplete(dev.langchain4j.model.output.Response<AiMessage> response) {
        // Convert Response<AiMessage> to ChatResponse
        ChatResponse chatResponse = ChatResponse.builder()
            .aiMessage(response.content())
            .build();
        onCompleteResponse(chatResponse);
    }
    
    /**
     * Cancel the streaming operation.
     */
    public void cancel() {
        this.cancelled = true;
    }
    
    /**
     * Get the complete message accumulated so far.
     */
    public String getCompleteMessage() {
        synchronized (currentMessage) {
            return currentMessage.toString();
        }
    }
    
    /**
     * Reset for a new message.
     */
    public void reset() {
        synchronized (currentMessage) {
            currentMessage.setLength(0);
        }
        this.cancelled = false;
    }
}

