package com.zenyard.ghidra.copilot.deepagent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.bsc.langgraph4j.action.AsyncNodeActionWithConfig;

import com.zenyard.ghidra.copilot.CopilotStreamHandler;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.langsmith.RunTree;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.StreamingChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
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
    private final LangSmithTracer tracer;

    public ResponseNode(
            ChatModel chatModel,
            StreamingChatModel streamingChatModel,
            CopilotStreamHandler streamHandler,
            String systemPrompt,
            boolean sanitizeToolMessages,
            long streamingTimeoutMs) {
        this(chatModel, streamingChatModel, streamHandler, systemPrompt,
                sanitizeToolMessages, streamingTimeoutMs, null);
    }

    public ResponseNode(
            ChatModel chatModel,
            StreamingChatModel streamingChatModel,
            CopilotStreamHandler streamHandler,
            String systemPrompt,
            boolean sanitizeToolMessages,
            long streamingTimeoutMs,
            LangSmithTracer tracer) {
        this.chatModel = chatModel;
        this.streamingChatModel = streamingChatModel;
        this.streamHandler = streamHandler;
        this.systemPrompt = systemPrompt;
        this.sanitizeToolMessages = sanitizeToolMessages;
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
        MessageSanitizer.SanitizeResult sanitizeResult = MessageSanitizer.sanitizeMessages(rawMessages, sanitizeToolMessages);
        List<ChatMessage> messages = sanitizeResult.messages();
        ghidra.util.Msg.debug(this, "ResponseNode input messages=" + messages.size());

        RunTree traceRun = beginResponseTrace(messages);

        if (streamingChatModel != null && streamHandler != null) {
            try {
                Map<String, Object> update = streamResponse(messages);
                long elapsedMs = Math.max(0L, (System.nanoTime() - startNs) / 1_000_000L);
                ghidra.util.Msg.info(this, "ResponseNode streaming success elapsedMs=" + elapsedMs);
                endResponseTrace(traceRun, update);
                return update;
            } catch (RuntimeException ex) {
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
        Map<String, Object> update = syncResponse(messages);
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
        ChatRequest request = ChatRequest.builder()
            .messages(messages)
            .build();
        ChatResponse response = chatModel.chat(request);
        AiMessage aiMessage = response.aiMessage();
        String text = aiMessage.text() != null ? aiMessage.text() : "";
        ghidra.util.Msg.debug(this, "ResponseNode sync aiTextLen=" + text.length());

        Map<String, Object> update = new HashMap<>();
        update.put(CopilotDeepState.MESSAGES, aiMessage);
        update.put(CopilotDeepState.FINAL_RESPONSE, text);
        long elapsedMs = Math.max(0L, (System.nanoTime() - startNs) / 1_000_000L);
        ghidra.util.Msg.debug(this, "ResponseNode syncResponse elapsedMs=" + elapsedMs);
        return update;
    }

    private Map<String, Object> streamResponse(List<ChatMessage> messages) {
        long startNs = System.nanoTime();
        ChatRequest request = ChatRequest.builder()
            .messages(messages)
            .build();

        CountDownLatch completion = new CountDownLatch(1);
        AtomicReference<String> finalText = new AtomicReference<>("");
        AtomicReference<Throwable> errorRef = new AtomicReference<>();

        StreamingChatResponseHandler handler = new StreamingChatResponseHandler() {
            @Override
            public void onPartialResponse(String partialResponse) {
                streamHandler.onPartialResponse(partialResponse);
            }

            @Override
            public void onCompleteResponse(ChatResponse completeResponse) {
                AiMessage message = completeResponse.aiMessage();
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
            if (!completion.await(streamingTimeoutMs, TimeUnit.MILLISECONDS)) {
                throw new RuntimeException("Streaming response did not complete in time (timeoutMs="
                    + streamingTimeoutMs + ")");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Streaming response interrupted", e);
        }

        if (errorRef.get() != null) {
            throw new RuntimeException("Streaming response failed", errorRef.get());
        }

        String resolvedText = finalText.get();
        if ((resolvedText == null || resolvedText.isBlank()) && chatModel != null) {
            ghidra.util.Msg.info(this, "ResponseNode stream produced empty text; running sync fallback request");
            ChatResponse fallbackResponse = chatModel.chat(request);
            AiMessage fallbackMessage = fallbackResponse.aiMessage();
            resolvedText = fallbackMessage != null && fallbackMessage.text() != null
                ? fallbackMessage.text()
                : "";
        }
        AiMessage aiMessage = AiMessage.from(resolvedText != null ? resolvedText : "");
        Map<String, Object> update = new HashMap<>();
        update.put(CopilotDeepState.MESSAGES, aiMessage);
        update.put(CopilotDeepState.FINAL_RESPONSE, resolvedText != null ? resolvedText : "");
        long elapsedMs = Math.max(0L, (System.nanoTime() - startNs) / 1_000_000L);
        ghidra.util.Msg.debug(this, "ResponseNode streamResponse elapsedMs=" + elapsedMs);
        return update;
    }

}
