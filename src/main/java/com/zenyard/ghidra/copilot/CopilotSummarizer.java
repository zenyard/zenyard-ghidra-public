package com.zenyard.ghidra.copilot;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import com.zenyard.ghidra.copilot.deepagent.MessageSummarizer;

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
    
    private static final int KEEP_RECENT_MESSAGES = 5;
    private static final int MIN_KEEP_RECENT_MESSAGES = 4;
    private static final int MAX_COMPACTION_PASSES = 3;
    
    private final StreamingChatModel summarizationModel;
    private final TokenCountEstimator tokenCountEstimator;

    public static final class CompactionRequest {
        private final int contextWindowTokens;
        private final double triggerFraction;
        private final int keepRecentMessages;
        private final int toolArgTruncateThreshold;
        private final int reserveTokens;
        private final boolean forceCompaction;
        private final int maxPasses;

        public CompactionRequest(
                int contextWindowTokens,
                double triggerFraction,
                int keepRecentMessages,
                int toolArgTruncateThreshold,
                int reserveTokens,
                boolean forceCompaction,
                int maxPasses) {
            this.contextWindowTokens = contextWindowTokens > 0 ? contextWindowTokens : 200_000;
            this.triggerFraction = (triggerFraction > 0.0 && triggerFraction <= 1.0) ? triggerFraction : 0.8;
            this.keepRecentMessages = keepRecentMessages > 0 ? keepRecentMessages : KEEP_RECENT_MESSAGES;
            this.toolArgTruncateThreshold = toolArgTruncateThreshold > 0 ? toolArgTruncateThreshold : 5_000;
            this.reserveTokens = Math.max(0, reserveTokens);
            this.forceCompaction = forceCompaction;
            this.maxPasses = maxPasses > 0 ? maxPasses : MAX_COMPACTION_PASSES;
        }

        public int contextWindowTokens() {
            return contextWindowTokens;
        }

        public double triggerFraction() {
            return triggerFraction;
        }

        public int keepRecentMessages() {
            return keepRecentMessages;
        }

        public int toolArgTruncateThreshold() {
            return toolArgTruncateThreshold;
        }

        public int reserveTokens() {
            return reserveTokens;
        }

        public boolean forceCompaction() {
            return forceCompaction;
        }

        public int maxPasses() {
            return maxPasses;
        }
    }

    public static final class CompactionResult {
        private final List<ChatMessage> messages;
        private final boolean compacted;
        private final int estimatedTokensBefore;
        private final int estimatedTokensAfter;
        private final int budgetTokens;
        private final int passes;

        public CompactionResult(
                List<ChatMessage> messages,
                boolean compacted,
                int estimatedTokensBefore,
                int estimatedTokensAfter,
                int budgetTokens,
                int passes) {
            this.messages = messages != null ? List.copyOf(messages) : List.of();
            this.compacted = compacted;
            this.estimatedTokensBefore = Math.max(0, estimatedTokensBefore);
            this.estimatedTokensAfter = Math.max(0, estimatedTokensAfter);
            this.budgetTokens = Math.max(0, budgetTokens);
            this.passes = Math.max(0, passes);
        }

        public List<ChatMessage> messages() {
            return messages;
        }

        public boolean compacted() {
            return compacted;
        }

        public int estimatedTokensBefore() {
            return estimatedTokensBefore;
        }

        public int estimatedTokensAfter() {
            return estimatedTokensAfter;
        }

        public int budgetTokens() {
            return budgetTokens;
        }

        public int passes() {
            return passes;
        }
    }
    
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
            if (memory == null) {
                return;
            }
            int currentTokenCount = memory.getCurrentTokenCount();
            int triggerThreshold = CopilotMemory.getSummarizationTrigger();
            if (currentTokenCount < triggerThreshold) {
                return;
            }
            CompactionResult result = compactMessages(
                memory.getMessages(),
                new CompactionRequest(
                    CopilotMemory.getMaxTokens(),
                    triggerThreshold / (double) CopilotMemory.getMaxTokens(),
                    KEEP_RECENT_MESSAGES,
                    5_000,
                    0,
                    false,
                    1
                ),
                null
            );
            if (result.compacted()) {
                memory.replaceMessages(result.messages());
            }
        } catch (Exception e) {
            Msg.warn(this, "Error during summarization: " + e.getMessage(), e);
        }
    }

    public CompactionResult compactMessages(
            List<ChatMessage> inputMessages,
            CompactionRequest request,
            Consumer<String> statusListener) {
        List<ChatMessage> initialMessages = inputMessages != null ? new ArrayList<>(inputMessages) : List.of();
        CompactionRequest effectiveRequest = request != null
            ? request
            : new CompactionRequest(200_000, 0.8, KEEP_RECENT_MESSAGES, 5_000, 0, false, MAX_COMPACTION_PASSES);

        int beforeTokens = estimateTokenCount(initialMessages);
        int budgetTokens = Math.max(1, effectiveRequest.contextWindowTokens() - effectiveRequest.reserveTokens());
        int triggerTokens = Math.min(
            budgetTokens,
            Math.max(1, (int) Math.floor(effectiveRequest.contextWindowTokens() * effectiveRequest.triggerFraction())));

        List<ChatMessage> workingMessages = MessageSummarizer.truncateToolArgsInList(
            initialMessages,
            effectiveRequest.toolArgTruncateThreshold());
        boolean compacted = estimateTokenCount(workingMessages) < beforeTokens;
        int passes = 0;

        while (passes < effectiveRequest.maxPasses()) {
            int estimatedTokens = estimateTokenCount(workingMessages);
            boolean overBudget = estimatedTokens > budgetTokens;
            boolean nearBudget = estimatedTokens >= triggerTokens;
            boolean shouldForcePass = effectiveRequest.forceCompaction() && passes == 0;
            if (!overBudget && !nearBudget && !shouldForcePass) {
                break;
            }

            int keepRecent = adjustKeepRecentMessages(
                effectiveRequest.keepRecentMessages(),
                effectiveRequest.forceCompaction(),
                passes);
            SummarySplit split = splitMessagesForSummary(workingMessages, keepRecent);
            if (split == null || split.olderMessages().isEmpty()) {
                break;
            }

            notifyStatus(statusListener, "Compacting conversation...");
            String summary = summarizeMessages(createSummarizationPrompt(split.olderMessages()));
            if (summary == null || summary.isBlank()) {
                break;
            }

            List<ChatMessage> compactedMessages = new ArrayList<>();
            if (split.systemMessage() != null) {
                compactedMessages.add(split.systemMessage());
            }
            compactedMessages.add(UserMessage.from(renderSummaryMessage(summary)));
            compactedMessages.addAll(MessageSummarizer.truncateToolArgsInList(
                split.recentMessages(),
                effectiveRequest.toolArgTruncateThreshold()));

            int nextTokens = estimateTokenCount(compactedMessages);
            if (nextTokens >= estimatedTokens && !effectiveRequest.forceCompaction()) {
                break;
            }

            workingMessages = compactedMessages;
            compacted = true;
            passes++;
        }

        int afterTokens = estimateTokenCount(workingMessages);
        return new CompactionResult(workingMessages, compacted, beforeTokens, afterTokens, budgetTokens, passes);
    }
    
    private SummarySplit splitMessagesForSummary(List<ChatMessage> messages, int keepRecent) {
        if (messages == null || messages.isEmpty()) {
            return null;
        }
        ChatMessage first = messages.get(0);
        boolean hasSystem = first instanceof SystemMessage;
        int conversationStart = hasSystem ? 1 : 0;
        int conversationCount = messages.size() - conversationStart;
        if (conversationCount <= keepRecent || conversationCount <= 1) {
            return null;
        }
        int splitIndex = messages.size() - keepRecent;
        List<ChatMessage> olderMessages = new ArrayList<>(messages.subList(conversationStart, splitIndex));
        List<ChatMessage> recentMessages = new ArrayList<>(messages.subList(splitIndex, messages.size()));
        return new SummarySplit(hasSystem ? first : null, olderMessages, recentMessages);
    }
    
    /**
     * Create a prompt for summarization.
     */
    private String createSummarizationPrompt(List<ChatMessage> oldMessages) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Summarize the following prior Copilot conversation so a later model call can continue the work with less context.\n");
        prompt.append("Preserve the user's goal, important facts discovered, tool outputs that matter, concrete symbol names or addresses, open questions, and pending next steps.\n");
        prompt.append("Use compact markdown with these sections exactly:\n");
        prompt.append("## Goal\n## Key Findings\n## Important Artifacts\n## Open Questions\n## Next Steps\n\n");
        prompt.append("Conversation history to summarize:\n\n");
        
        for (ChatMessage message : oldMessages) {
            if (message instanceof UserMessage) {
                prompt.append("User: ").append(extractTextFromMessage(message)).append("\n");
            } else if (message instanceof AiMessage) {
                prompt.append("Assistant: ").append(extractTextFromMessage(message)).append("\n");
            } else if (message instanceof SystemMessage) {
                continue;
            } else {
                prompt.append(extractTextFromMessage(message)).append("\n");
            }
        }
        
        prompt.append("\nWrite only the compact summary. Do not add preamble or commentary.");
        
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
    
    private String renderSummaryMessage(String summary) {
        return "Conversation summary from earlier turns. Treat this as condensed memory for continuity.\n\n"
            + summary.trim();
    }

    private void notifyStatus(Consumer<String> statusListener, String message) {
        if (statusListener != null && message != null && !message.isBlank()) {
            statusListener.accept(message);
        }
    }

    public int estimateTokenCount(List<ChatMessage> messages) {
        if (messages == null || messages.isEmpty()) {
            return 0;
        }
        if (tokenCountEstimator != null) {
            return tokenCountEstimator.estimateTokenCountInMessages(messages);
        }
        int total = 0;
        for (ChatMessage message : messages) {
            total += estimateTokenCount(extractTextFromMessage(message));
        }
        return total;
    }

    public int estimateTokenCount(String text) {
        String safeText = text != null ? text : "";
        if (safeText.isEmpty()) {
            return 0;
        }
        if (tokenCountEstimator != null) {
            return tokenCountEstimator.estimateTokenCountInText(safeText);
        }
        return Math.max(1, safeText.length() / 4);
    }

    private int adjustKeepRecentMessages(int configuredKeepRecent, boolean forceCompaction, int passes) {
        int keepRecent = Math.max(MIN_KEEP_RECENT_MESSAGES, configuredKeepRecent);
        if (!forceCompaction && passes == 0) {
            return keepRecent;
        }
        for (int i = 0; i <= passes; i++) {
            if (keepRecent <= MIN_KEEP_RECENT_MESSAGES) {
                break;
            }
            keepRecent = Math.max(MIN_KEEP_RECENT_MESSAGES, keepRecent / 2);
        }
        return keepRecent;
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
            return message.toString();
        }
    }

    private static final class SummarySplit {
        private final ChatMessage systemMessage;
        private final List<ChatMessage> olderMessages;
        private final List<ChatMessage> recentMessages;

        private SummarySplit(
                ChatMessage systemMessage,
                List<ChatMessage> olderMessages,
                List<ChatMessage> recentMessages) {
            this.systemMessage = systemMessage;
            this.olderMessages = olderMessages;
            this.recentMessages = recentMessages;
        }

        private ChatMessage systemMessage() {
            return systemMessage;
        }

        private List<ChatMessage> olderMessages() {
            return olderMessages;
        }

        private List<ChatMessage> recentMessages() {
            return recentMessages;
        }
    }
}

