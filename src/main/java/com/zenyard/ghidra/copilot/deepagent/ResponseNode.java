package com.zenyard.ghidra.copilot.deepagent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.bsc.langgraph4j.action.AsyncNodeActionWithConfig;

import com.zenyard.ghidra.copilot.CopilotSummarizer;
import com.zenyard.ghidra.copilot.CopilotStreamHandler;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.data.message.ToolExecutionResultMessage;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.langsmith.RunTree;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.StreamingChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ChatRequestParameters;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.chat.response.StreamingChatResponseHandler;

/**
 * Final response node with optional streaming.
 */
public class ResponseNode implements AsyncNodeActionWithConfig<CopilotDeepState> {

    private final ChatModel chatModel;
    private final StreamingChatModel streamingChatModel;
    private final CopilotStreamHandler streamHandler;
    private final String systemPrompt;
    private final boolean sanitizeToolMessages;
    private final long streamingTimeoutMs;
    private final CopilotSummarizer summarizer;
    private final CopilotDeepAgentConfig deepAgentConfig;
    private final LangSmithTracer tracer;
    private final List<ToolSpecification> toolSpecifications;

    public ResponseNode(
            ChatModel chatModel,
            StreamingChatModel streamingChatModel,
            CopilotStreamHandler streamHandler,
            String systemPrompt,
            boolean sanitizeToolMessages,
            long streamingTimeoutMs) {
        this(chatModel, streamingChatModel, streamHandler, List.of(), systemPrompt,
                sanitizeToolMessages, null, null, streamingTimeoutMs, null);
    }

    public ResponseNode(
            ChatModel chatModel,
            StreamingChatModel streamingChatModel,
            CopilotStreamHandler streamHandler,
            String systemPrompt,
            boolean sanitizeToolMessages,
            long streamingTimeoutMs,
            LangSmithTracer tracer) {
        this(chatModel, streamingChatModel, streamHandler, List.of(), systemPrompt,
            sanitizeToolMessages, null, null, streamingTimeoutMs, tracer);
    }

    public ResponseNode(
            ChatModel chatModel,
            StreamingChatModel streamingChatModel,
            CopilotStreamHandler streamHandler,
            List<ToolSpecification> toolSpecifications,
            String systemPrompt,
            boolean sanitizeToolMessages,
            CopilotSummarizer summarizer,
            CopilotDeepAgentConfig deepAgentConfig,
            long streamingTimeoutMs,
            LangSmithTracer tracer) {
        this.chatModel = chatModel;
        this.streamingChatModel = streamingChatModel;
        this.streamHandler = streamHandler;
        this.toolSpecifications = toolSpecifications != null ? toolSpecifications : List.of();
        this.systemPrompt = systemPrompt;
        this.sanitizeToolMessages = sanitizeToolMessages;
        this.summarizer = summarizer;
        this.deepAgentConfig = deepAgentConfig != null ? deepAgentConfig : CopilotDeepAgentConfig.defaults();
        this.streamingTimeoutMs = streamingTimeoutMs > 0 ? streamingTimeoutMs : 120_000L;
        this.tracer = tracer;
    }

    @Override
    public CompletableFuture<Map<String, Object>> apply(
            CopilotDeepState state,
            org.bsc.langgraph4j.RunnableConfig config) {
        return CompletableFuture.supplyAsync(() -> buildResponse(state));
    }

    Map<String, Object> buildFinalResponse(CopilotDeepState state) {
        return buildResponse(state);
    }

    private Map<String, Object> buildResponse(CopilotDeepState state) {
        long startNs = System.nanoTime();
        String existingFinal = state.finalResponse().orElse("");
        if (existingFinal != null && !existingFinal.isBlank()) {
            ghidra.util.Msg.debug(this, "ResponseNode reused existing final text len=" + existingFinal.length());
            return Map.of(CopilotDeepState.FINAL_RESPONSE, existingFinal);
        }
        List<ChatMessage> rawMessages = new ArrayList<>();
        rawMessages.add(SystemMessage.from(systemPrompt));
        rawMessages.addAll(state.messages());
        List<ChatMessage> patched = MessageSanitizer.patchDanglingToolCalls(rawMessages);
        MessageSanitizer.SanitizeResult sanitizeResult = MessageSanitizer.sanitizeMessages(patched, sanitizeToolMessages);
        List<ChatMessage> baseMessages = new ArrayList<>(sanitizeResult.messages());
        state.loopGuardMessage().ifPresent(hint -> baseMessages.add(UserMessage.from(hint)));
        baseMessages.add(UserMessage.from(
            "Provide your final answer now as plain text. Do not call any tools."));
        ghidra.util.Msg.debug(this, "ResponseNode input messages=" + baseMessages.size());

        if (streamHandler != null) {
            streamHandler.prepareForFinalResponse();
        }

        List<ChatMessage> messages = compactMessagesForRequest(baseMessages, false);
        RunTree traceRun = beginResponseTrace(messages);

        if (streamingChatModel != null && streamHandler != null) {
            try {
                Map<String, Object> update = streamResponse(messages);
                long elapsedMs = Math.max(0L, (System.nanoTime() - startNs) / 1_000_000L);
                ghidra.util.Msg.info(this, "ResponseNode streaming success elapsedMs=" + elapsedMs);
                endResponseTrace(traceRun, update);
                return update;
            } catch (CancellationException ce) {
                endResponseTraceWithError(traceRun, ce);
                throw ce;
            } catch (RuntimeException ex) {
                if (shouldRetryPromptTooLong(ex)) {
                    List<ChatMessage> retryMessages = compactMessagesForRequest(baseMessages, true);
                    traceRun = beginResponseTrace(retryMessages);
                    Map<String, Object> update = syncResponse(retryMessages);
                    endResponseTrace(traceRun, update);
                    return update;
                }
                ghidra.util.Msg.warn(this, "Streaming response failed, falling back to sync: " + ex.getMessage());
                endResponseTraceWithError(traceRun, ex);
                traceRun = beginResponseTrace(messages);
                Map<String, Object> update = syncResponse(messages);
                long elapsedMs = Math.max(0L, (System.nanoTime() - startNs) / 1_000_000L);
                ghidra.util.Msg.info(this, "ResponseNode fallback-to-sync elapsedMs=" + elapsedMs);
                endResponseTrace(traceRun, update);
                return update;
            }
        }
        Map<String, Object> update;
        try {
            update = syncResponse(messages);
        } catch (RuntimeException ex) {
            if (!shouldRetryPromptTooLong(ex)) {
                throw ex;
            }
            List<ChatMessage> retryMessages = compactMessagesForRequest(baseMessages, true);
            traceRun = beginResponseTrace(retryMessages);
            update = syncResponse(retryMessages);
        }
        long elapsedMs = Math.max(0L, (System.nanoTime() - startNs) / 1_000_000L);
        ghidra.util.Msg.info(this, "ResponseNode sync-only elapsedMs=" + elapsedMs);
        endResponseTrace(traceRun, update);
        return update;
    }

    private RunTree beginResponseTrace(List<ChatMessage> messages) {
        if (tracer == null || !tracer.isEnabled()) {
            return null;
        }
        return tracer.beginLlmRun(tracer.getCurrentRoot(), "response", "messages=" + messages.size());
    }

    private void endResponseTrace(RunTree run, Map<String, Object> update) {
        if (tracer == null || run == null) {
            return;
        }
        Object text = update.get(CopilotDeepState.FINAL_RESPONSE);
        int len = text instanceof String s ? s.length() : 0;
        tracer.endRun(run, LangSmithTracer.outputsOf("text_length", String.valueOf(len)));
    }

    private void endResponseTraceWithError(RunTree run, Throwable error) {
        if (tracer == null || run == null) {
            return;
        }
        tracer.endRunWithError(run, error.getMessage());
    }

    private Map<String, Object> syncResponse(List<ChatMessage> messages) {
        long startNs = System.nanoTime();
        ChatRequest request = buildRequest(messages);
        ChatResponse response = chatModel.chat(request);
        AiMessage aiMessage = response.aiMessage();
        String text = aiMessage != null && aiMessage.text() != null ? aiMessage.text() : "";
        if (text.isBlank() || hasToolCalls(aiMessage)) {
            text = forceTextOnlyResponse(messages, "sync");
        }
        ghidra.util.Msg.debug(this, "ResponseNode sync aiTextLen=" + text.length());

        Map<String, Object> update = new HashMap<>();
        update.put(CopilotDeepState.MESSAGES, AiMessage.from(text));
        update.put(CopilotDeepState.FINAL_RESPONSE, text);
        long elapsedMs = Math.max(0L, (System.nanoTime() - startNs) / 1_000_000L);
        ghidra.util.Msg.debug(this, "ResponseNode syncResponse elapsedMs=" + elapsedMs);
        return update;
    }

    private static final long CANCELLATION_POLL_MS = 500L;

    private Map<String, Object> streamResponse(List<ChatMessage> messages) {
        if (streamHandler.isCancelled()) {
            throw new CancellationException("Operation cancelled");
        }

        long startNs = System.nanoTime();
        ChatRequest request = buildRequest(messages);

        CountDownLatch completion = new CountDownLatch(1);
        AtomicReference<String> finalText = new AtomicReference<>("");
        AtomicReference<AiMessage> finalMessage = new AtomicReference<>();
        AtomicReference<Throwable> errorRef = new AtomicReference<>();

        StreamingChatResponseHandler handler = new StreamingChatResponseHandler() {
            @Override
            public void onPartialResponse(String partialResponse) {
                if (streamHandler.isCancelled()) {
                    completion.countDown();
                    return;
                }
                streamHandler.onPartialResponse(partialResponse);
            }

            @Override
            public void onCompleteResponse(ChatResponse completeResponse) {
                AiMessage message = completeResponse.aiMessage();
                finalMessage.set(message);
                finalText.set(message.text() != null ? message.text() : "");
                streamHandler.onCompleteResponse(completeResponse);
                completion.countDown();
            }

            @Override
            public void onError(Throwable error) {
                errorRef.set(error);
                streamHandler.onError(error);
                completion.countDown();
            }
        };

        streamingChatModel.chat(request, handler);

        try {
            long remainingMs = streamingTimeoutMs;
            while (remainingMs > 0) {
                long pollMs = Math.min(CANCELLATION_POLL_MS, remainingMs);
                if (completion.await(pollMs, TimeUnit.MILLISECONDS)) {
                    break;
                }
                if (streamHandler.isCancelled()) {
                    throw new CancellationException("Operation cancelled");
                }
                remainingMs -= pollMs;
            }
            if (remainingMs <= 0 && completion.getCount() > 0) {
                throw new RuntimeException("Streaming response did not complete in time (timeoutMs="
                    + streamingTimeoutMs + ")");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Streaming response interrupted", e);
        }

        if (streamHandler.isCancelled()) {
            throw new CancellationException("Operation cancelled");
        }

        if (errorRef.get() != null) {
            throw new RuntimeException("Streaming response failed", errorRef.get());
        }

        String resolvedText = finalText.get();
        if ((resolvedText == null || resolvedText.isBlank() || hasToolCalls(finalMessage.get())) && chatModel != null) {
            ghidra.util.Msg.info(this, "ResponseNode stream produced empty text; running sync fallback request");
            ChatResponse fallbackResponse = chatModel.chat(request);
            AiMessage fallbackMessage = fallbackResponse.aiMessage();
            resolvedText = fallbackMessage != null && fallbackMessage.text() != null
                ? fallbackMessage.text()
                : "";
            if (resolvedText.isBlank() || hasToolCalls(fallbackMessage)) {
                resolvedText = forceTextOnlyResponse(messages, "stream");
            }
        }
        AiMessage aiMessage = AiMessage.from(resolvedText != null ? resolvedText : "");
        Map<String, Object> update = new HashMap<>();
        update.put(CopilotDeepState.MESSAGES, aiMessage);
        update.put(CopilotDeepState.FINAL_RESPONSE, resolvedText != null ? resolvedText : "");
        long elapsedMs = Math.max(0L, (System.nanoTime() - startNs) / 1_000_000L);
        ghidra.util.Msg.debug(this, "ResponseNode streamResponse elapsedMs=" + elapsedMs);
        return update;
    }

    private String forceTextOnlyResponse(List<ChatMessage> messages, String mode) {
        if (chatModel == null) {
            return "";
        }
        try {
            List<ChatMessage> patched = MessageSanitizer.patchDanglingToolCalls(messages);
            List<ChatMessage> textOnlyHistory = MessageSanitizer
                .sanitizeMessages(patched, true)
                .messages();
            List<ChatMessage> promptMessages = new ArrayList<>(textOnlyHistory);
            promptMessages.add(UserMessage.from(
                "Provide the final answer now. Return plain text only and do not call any tools. "
                + "Summarize what was investigated, what was found, and recommend the next concrete step "
                + "using a different approach if the current one has not made progress."));
            ChatRequest textOnlyRequest = ChatRequest.builder()
                .messages(promptMessages)
                .build();
            ChatResponse textOnlyResponse = chatModel.chat(textOnlyRequest);
            AiMessage textOnlyMessage = textOnlyResponse.aiMessage();
            String text = textOnlyMessage != null && textOnlyMessage.text() != null
                ? textOnlyMessage.text()
                : "";
            if (!text.isBlank()) {
                return text;
            }
            ghidra.util.Msg.warn(this, "ResponseNode " + mode
                + " text-only fallback also returned empty text");
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "ResponseNode " + mode
                + " text-only fallback failed: " + e.getMessage());
        }
        return "I completed the analysis steps but couldn't generate a final response. "
            + "Please try once more and I will summarize the result directly.";
    }

    private static boolean hasToolCalls(AiMessage message) {
        return message != null
            && message.toolExecutionRequests() != null
            && !message.toolExecutionRequests().isEmpty();
    }

    private ChatRequest buildRequest(List<ChatMessage> messages) {
        ChatRequest.Builder builder = ChatRequest.builder().messages(messages);
        if (shouldAttachToolSpecifications(messages)) {
            builder.parameters(ChatRequestParameters.builder()
                .toolSpecifications(toolSpecifications)
                .build());
        }
        return builder.build();
    }

    private boolean shouldAttachToolSpecifications(List<ChatMessage> messages) {
        if (toolSpecifications == null || toolSpecifications.isEmpty() || messages == null || messages.isEmpty()) {
            return false;
        }
        for (ChatMessage message : messages) {
            if (message instanceof ToolExecutionResultMessage) {
                return true;
            }
            if (message instanceof AiMessage aiMessage
                    && aiMessage.toolExecutionRequests() != null
                    && !aiMessage.toolExecutionRequests().isEmpty()) {
                return true;
            }
        }
        return false;
    }

    private List<ChatMessage> compactMessagesForRequest(List<ChatMessage> messages, boolean aggressiveRetry) {
        if (summarizer == null) {
            return MessageSummarizer.truncateToolArgsInList(
                messages,
                deepAgentConfig.toolArgTruncateThreshold());
        }
        int reserveTokens = deepAgentConfig.requestTokenReserveTokens()
            + (shouldAttachToolSpecifications(messages) ? estimateToolSpecificationTokens(toolSpecifications) : 0)
            + (aggressiveRetry ? deepAgentConfig.promptTooLongRetryExtraReserveTokens() : 0);
        CopilotSummarizer.CompactionResult result = summarizer.compactMessages(
            messages,
            new CopilotSummarizer.CompactionRequest(
                deepAgentConfig.contextWindowTokens(),
                deepAgentConfig.summarizationTriggerFraction(),
                deepAgentConfig.summarizationKeepMessages(),
                deepAgentConfig.toolArgTruncateThreshold(),
                reserveTokens,
                aggressiveRetry,
                aggressiveRetry ? 3 : 2
            ),
            this::showCompactionStatus
        );
        ghidra.util.Msg.info(this,
            "ResponseNode compaction: aggressiveRetry=" + aggressiveRetry
                + " compacted=" + result.compacted()
                + " beforeTokens=" + result.estimatedTokensBefore()
                + " afterTokens=" + result.estimatedTokensAfter()
                + " budgetTokens=" + result.budgetTokens()
                + " passes=" + result.passes());
        return result.messages();
    }

    private int estimateToolSpecificationTokens(List<ToolSpecification> specs) {
        if (specs == null || specs.isEmpty() || summarizer == null) {
            return 0;
        }
        return summarizer.estimateTokenCount(String.valueOf(specs));
    }

    private void showCompactionStatus(String status) {
        if (streamHandler != null) {
            streamHandler.appendStatusLine(status);
        }
    }

    private boolean shouldRetryPromptTooLong(Throwable throwable) {
        return deepAgentConfig.promptTooLongCompactionRetryEnabled()
            && isPromptTooLongError(throwable);
    }

    private boolean isPromptTooLongError(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            String message = current.getMessage();
            if (message != null) {
                String lower = message.toLowerCase(java.util.Locale.ROOT);
                if (lower.contains("prompt is too long")
                        || lower.contains("token limit")
                        || lower.contains("context length")
                        || lower.contains("input is too long")
                        || lower.contains("tokens >")) {
                    return true;
                }
            }
            current = current.getCause();
        }
        return false;
    }

}
