package com.zenyard.ghidra.copilot;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.StreamingChatModel;
import dev.langchain4j.model.TokenCountEstimator;
import ghidra.util.Msg;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Handles summarization of conversation history to preserve context.
 * Mirrors IDA's SummarizationMiddleware behavior.
 * 
 * When token count approaches the limit (140k tokens), summarizes old messages
 * and replaces them with a summary message, keeping recent messages intact.
 */
public class CopilotSummarizer {
    
    private static final int KEEP_RECENT_MESSAGES = 5; // Keep last 5 messages without summarization
    
    private final StreamingChatModel summarizationModel;
    private final TokenCountEstimator tokenCountEstimator;
    
    public CopilotSummarizer(StreamingChatModel summarizationModel, TokenCountEstimator tokenCountEstimator) {
        this.summarizationModel = summarizationModel;
        this.tokenCountEstimator = tokenCountEstimator;
    }
    
    /**
     * Check if summarization is needed and perform it if so.
     * Called after messages are added to memory.
     */
    public void summarizeIfNeeded(CopilotMemory memory) {
        try {
            int currentTokenCount = memory.getCurrentTokenCount();
            int triggerThreshold = CopilotMemory.getSummarizationTrigger();
            
            if (currentTokenCount < triggerThreshold) {
                // Not yet at threshold, no summarization needed
                return;
            }
            
            // Get all messages
            List<ChatMessage> allMessages = memory.getMessages();
            
            if (allMessages.size() <= KEEP_RECENT_MESSAGES) {
                // Not enough messages to summarize
                return;
            }
            
            // Split messages into old (to summarize) and recent (to keep)
            List<ChatMessage> oldMessages = getOldMessages(allMessages, KEEP_RECENT_MESSAGES);
            List<ChatMessage> recentMessages = allMessages.subList(
                allMessages.size() - KEEP_RECENT_MESSAGES, 
                allMessages.size()
            );
            
            // Create summarization prompt
            String summarizationPrompt = createSummarizationPrompt(oldMessages);
            
            // Call summarization LLM
            String summary = summarizeMessages(summarizationPrompt);
            
            // Replace old messages with summary message
            replaceMessagesWithSummary(memory, oldMessages, recentMessages, summary);
            
            Msg.info(this, "Summarized " + oldMessages.size() + " messages into summary. " 
                          + "Kept " + recentMessages.size() + " recent messages.");
            
        } catch (Exception e) {
            // Log error but don't block conversation
            Msg.warn(this, "Error during summarization: " + e.getMessage(), e);
        }
    }
    
    /**
     * Get old messages to summarize (all except the last N recent messages).
     */
    private List<ChatMessage> getOldMessages(List<ChatMessage> allMessages, int keepRecent) {
        if (allMessages.size() <= keepRecent) {
            return new ArrayList<>();
        }
        return new ArrayList<>(allMessages.subList(0, allMessages.size() - keepRecent));
    }
    
    /**
     * Create a prompt for summarization.
     */
    private String createSummarizationPrompt(List<ChatMessage> oldMessages) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Summarize the following conversation history, preserving important context, decisions made, and key information. ");
        prompt.append("The summary should be concise but comprehensive enough to maintain context for future interactions.\n\n");
        prompt.append("Conversation history to summarize:\n\n");
        
        for (ChatMessage message : oldMessages) {
            if (message instanceof UserMessage) {
                prompt.append("User: ").append(extractTextFromMessage(message)).append("\n");
            } else if (message instanceof AiMessage) {
                prompt.append("Assistant: ").append(extractTextFromMessage(message)).append("\n");
            } else if (message instanceof SystemMessage) {
                // Skip system messages in summary (they're part of the agent setup)
                continue;
            } else {
                prompt.append(extractTextFromMessage(message)).append("\n");
            }
        }
        
        prompt.append("\nPlease provide a concise summary that preserves the key information and context from this conversation.");
        
        return prompt.toString();
    }
    
    /**
     * Summarize messages using the summarization LLM.
     */
    private String summarizeMessages(String prompt) {
        try {
            StringBuilder summaryBuilder = new StringBuilder();
            CountDownLatch completion = new CountDownLatch(1);
            AtomicReference<Throwable> errorHolder = new AtomicReference<>();

            summarizationModel.chat(prompt, new dev.langchain4j.model.chat.response.StreamingChatResponseHandler() {
                @Override
                public void onPartialResponse(String partialResponse) {
                    summaryBuilder.append(partialResponse);
                }

                @Override
                public void onCompleteResponse(dev.langchain4j.model.chat.response.ChatResponse completeResponse) {
                    if (completeResponse.aiMessage() != null && completeResponse.aiMessage().text() != null) {
                        summaryBuilder.setLength(0);
                        summaryBuilder.append(completeResponse.aiMessage().text());
                    }
                    completion.countDown();
                }

                @Override
                public void onError(Throwable error) {
                    errorHolder.set(error);
                    completion.countDown();
                }
            });

            boolean finished = completion.await(120, TimeUnit.SECONDS);
            if (!finished) {
                throw new RuntimeException("Summarization streaming did not complete in time");
            }
            if (errorHolder.get() != null) {
                Throwable error = errorHolder.get();
                throw error instanceof Exception ? (Exception) error : new RuntimeException(error);
            }
            return summaryBuilder.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate summary: " + e.getMessage(), e);
        }
    }
    
    /**
     * Replace old messages with a summary message, keeping recent messages.
     */
    private void replaceMessagesWithSummary(
            CopilotMemory memory, 
            List<ChatMessage> oldMessages, 
            List<ChatMessage> recentMessages,
            String summary) {
        
        // Create a new message list: summary message + recent messages
        List<ChatMessage> newMessages = new ArrayList<>();
        
        // Add summary as an AI message to preserve it in conversation context
        // Format: indicate it's a summary of previous conversation
        newMessages.add(AiMessage.aiMessage(
            "[Summary of previous conversation: " + summary + "]"
        ));
        
        // Add recent messages
        newMessages.addAll(recentMessages);
        
        // Replace messages in memory
        memory.replaceMessages(newMessages);
    }
    
    /**
     * Extract text from a ChatMessage, handling different message types.
     */
    private String extractTextFromMessage(ChatMessage message) {
        if (message instanceof UserMessage) {
            return ((UserMessage) message).singleText();
        } else if (message instanceof AiMessage) {
            return ((AiMessage) message).text();
        } else if (message instanceof SystemMessage) {
            return ((SystemMessage) message).text();
        } else {
            // Fallback: use toString() for other message types
            return message.toString();
        }
    }
}

