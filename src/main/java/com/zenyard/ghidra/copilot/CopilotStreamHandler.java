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
    private static final int MAX_STREAM_BUFFER_CHARS = 256_000;
    
    private final CopilotViewModel viewModel;
    private final StringBuilder currentMessage;
    private volatile boolean cancelled;
    private volatile boolean inPlanningPhase;
    
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
            if (currentMessage.length() > MAX_STREAM_BUFFER_CHARS) {
                int trim = currentMessage.length() - MAX_STREAM_BUFFER_CHARS;
                currentMessage.delete(0, trim);
            }
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
     * Signal the start of the planning phase.
     * Planning tokens will be shown in a "Reasoning..." thinking area in the UI.
     */
    public void beginPlanningPhase() {
        inPlanningPhase = true;
        SwingUtilities.invokeLater(() -> viewModel.setThinking(true, "Reasoning..."));
    }

    /**
     * Stream a planning token during the model's reasoning phase.
     * These tokens are displayed in the thinking/reasoning UI area.
     */
    public void onPlanningToken(String token) {
        if (cancelled) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            if (!cancelled && inPlanningPhase) {
                viewModel.appendThinkingText(token);
            }
        });
    }

    /**
     * Signal the end of the planning phase.
     * Clears the thinking area so the response area can take over.
     */
    public void endPlanningPhase() {
        inPlanningPhase = false;
        SwingUtilities.invokeLater(() -> viewModel.clearThinkingText());
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
        this.inPlanningPhase = false;
    }

}

