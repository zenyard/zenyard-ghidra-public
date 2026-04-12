package com.zenyard.ghidra.copilot.deepagent;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;

import org.bsc.langgraph4j.RunnableConfig;
import org.bsc.langgraph4j.action.AsyncNodeActionWithConfig;

import com.zenyard.ghidra.copilot.CopilotPrompts;
import com.zenyard.ghidra.copilot.CopilotSummarizer;
import com.zenyard.ghidra.copilot.CopilotStreamHandler;

import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.langsmith.RunTree;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.StreamingChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ChatRequestParameters;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.chat.response.StreamingChatResponseHandler;

/**
 * Model node: runs the primary LLM loop and emits tool calls or responses.
 * Supports optional streaming to push planning tokens to the UI.
 */
public class PlanNode implements AsyncNodeActionWithConfig<CopilotDeepState> {

    private final ChatModel chatModel;
    private final StreamingChatModel streamingChatModel;
    private final CopilotStreamHandler streamHandler;
    private final List<ToolSpecification> toolSpecifications;
    private final String systemPrompt;
    private final boolean sanitizeToolMessages;
    private final CopilotSummarizer summarizer;
    private final CopilotDeepAgentConfig deepAgentConfig;
    private final LangSmithTracer tracer;

    public PlanNode(
            ChatModel chatModel,
            List<ToolSpecification> toolSpecifications,
            String systemPrompt,
            boolean sanitizeToolMessages) {
        this(chatModel, null, null, toolSpecifications, systemPrompt, sanitizeToolMessages, null, null, null);
    }

    public PlanNode(
            ChatModel chatModel,
            StreamingChatModel streamingChatModel,
            CopilotStreamHandler streamHandler,
            List<ToolSpecification> toolSpecifications,
            String systemPrompt,
            boolean sanitizeToolMessages,
            CopilotSummarizer summarizer,
            CopilotDeepAgentConfig deepAgentConfig,
            LangSmithTracer tracer) {
        this.chatModel = chatModel;
        this.streamingChatModel = streamingChatModel;
        this.streamHandler = streamHandler;
        this.toolSpecifications = toolSpecifications;
        this.systemPrompt = systemPrompt;
        this.sanitizeToolMessages = sanitizeToolMessages;
        this.summarizer = summarizer;
        this.deepAgentConfig = deepAgentConfig != null ? deepAgentConfig : CopilotDeepAgentConfig.defaults();
        this.tracer = tracer;
    }

    @Override
    public CompletableFuture<Map<String, Object>> apply(CopilotDeepState state, RunnableConfig config) {
        String skillsSection = state.skillsPrompt().orElse("");
        String resolvedSystemPrompt = systemPrompt + "\n\n" + skillsSection + "\n\n" + orchestrationInstructions();
        int systemPromptReserve = MessageSummarizer.estimateTextTokens(resolvedSystemPrompt);

        java.util.ArrayList<ChatMessage> rawMessages = new java.util.ArrayList<>();
        rawMessages.add(SystemMessage.from(resolvedSystemPrompt));
        rawMessages.addAll(state.messages());
        List<ChatMessage> patchedMessages = MessageSanitizer.patchDanglingToolCalls(rawMessages);
        MessageSanitizer.SanitizeResult sanitizeResult = MessageSanitizer.sanitizeMessages(patchedMessages, sanitizeToolMessages);
        List<ChatMessage> baseMessages = sanitizeResult.messages();
        ghidra.util.Msg.debug(this, "PlanNode input messages=" + baseMessages.size());

        ChatRequestParameters parameters = ChatRequestParameters.builder()
            .toolSpecifications(toolSpecifications)
            .build();

        List<ChatMessage> preparedMessages = compactMessagesForRequest(baseMessages, false, systemPromptReserve);
        if (streamingChatModel != null && streamHandler != null) {
            CompletableFuture<Map<String, Object>> future = streamPlan(preparedMessages, parameters);
            return withPromptTooLongRetry(future, baseMessages, parameters, systemPromptReserve);
        }
        try {
            return CompletableFuture.completedFuture(syncPlan(preparedMessages, parameters));
        } catch (RuntimeException e) {
            if (!shouldRetryPromptTooLong(e)) {
                throw e;
            }
            List<ChatMessage> retryMessages = compactMessagesForRequest(baseMessages, true, systemPromptReserve);
            return CompletableFuture.completedFuture(syncPlan(retryMessages, parameters));
        }
    }

    private Map<String, Object> syncPlan(List<ChatMessage> messages, ChatRequestParameters parameters) {
        RunTree traceRun = beginPlanTrace(messages);

        ChatRequest request = ChatRequest.builder()
            .messages(messages)
            .parameters(parameters)
            .build();

        try {
            ChatResponse response = chatModel.chat(request);
            AiMessage aiMessage = response.aiMessage();
            logAiMessage(aiMessage);
            endPlanTrace(traceRun, aiMessage);
            return buildUpdate(aiMessage);
        } catch (Exception e) {
            endPlanTraceWithError(traceRun, e);
            throw e;
        }
    }

    private CompletableFuture<Map<String, Object>> streamPlan(
            List<ChatMessage> messages,
            ChatRequestParameters parameters) {
        if (streamHandler.isCancelled()) {
            return CompletableFuture.failedFuture(new CancellationException("Operation cancelled"));
        }
        CompletableFuture<Map<String, Object>> future = new CompletableFuture<>();
        streamHandler.beginPlanningPhase();
        RunTree traceRun = beginPlanTrace(messages);

        ChatRequest request = ChatRequest.builder()
            .messages(messages)
            .parameters(parameters)
            .build();

        streamingChatModel.chat(request, new StreamingChatResponseHandler() {
            @Override
            public void onPartialResponse(String partialResponse) {
                if (streamHandler.isCancelled()) {
                    streamHandler.endPlanningPhase();
                    endPlanTraceWithError(traceRun, new CancellationException("Cancelled"));
                    future.completeExceptionally(new CancellationException("Operation cancelled"));
                    return;
                }
                streamHandler.onPlanningToken(partialResponse);
            }

            @Override
            public void onCompleteResponse(ChatResponse response) {
                streamHandler.endPlanningPhase();
                if (streamHandler.isCancelled()) {
                    endPlanTraceWithError(traceRun, new CancellationException("Cancelled"));
                    future.completeExceptionally(new CancellationException("Operation cancelled"));
                    return;
                }
                AiMessage aiMessage = response.aiMessage();
                logAiMessage(aiMessage);
                endPlanTrace(traceRun, aiMessage);
                future.complete(buildUpdate(aiMessage));
            }

            @Override
            public void onError(Throwable error) {
                streamHandler.endPlanningPhase();
                if (streamHandler.isCancelled()) {
                    endPlanTraceWithError(traceRun, new CancellationException("Cancelled"));
                    future.completeExceptionally(new CancellationException("Operation cancelled"));
                    return;
                }
                ghidra.util.Msg.warn(PlanNode.this, "PlanNode streaming failed, falling back to sync: " + error.getMessage());
                endPlanTraceWithError(traceRun, error);
                try {
                    Map<String, Object> update = syncPlan(messages, parameters);
                    future.complete(update);
                } catch (Exception syncError) {
                    future.completeExceptionally(syncError);
                }
            }
        });

        return future;
    }

    private CompletableFuture<Map<String, Object>> withPromptTooLongRetry(
            CompletableFuture<Map<String, Object>> future,
            List<ChatMessage> baseMessages,
            ChatRequestParameters parameters,
            int systemPromptReserve) {
        return future.handle((result, throwable) -> {
            if (throwable == null) {
                return CompletableFuture.completedFuture(result);
            }
            Throwable cause = unwrapThrowable(throwable);
            if (!shouldRetryPromptTooLong(cause)) {
                return CompletableFuture.<Map<String, Object>>failedFuture(cause);
            }
            List<ChatMessage> retryMessages = compactMessagesForRequest(baseMessages, true, systemPromptReserve);
            try {
                return CompletableFuture.completedFuture(syncPlan(retryMessages, parameters));
            } catch (RuntimeException retryError) {
                return CompletableFuture.<Map<String, Object>>failedFuture(retryError);
            }
        }).thenCompose(java.util.function.Function.identity());
    }

    private List<ChatMessage> compactMessagesForRequest(
            List<ChatMessage> messages,
            boolean aggressiveRetry,
            int extraReserveTokens) {
        if (summarizer == null) {
            return MessageSummarizer.truncateToolArgsInList(
                messages,
                deepAgentConfig.toolArgTruncateThreshold());
        }
        int reserveTokens = deepAgentConfig.requestTokenReserveTokens()
            + MessageSummarizer.estimateToolSpecificationTokens(toolSpecifications)
            + Math.max(0, extraReserveTokens)
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
            "PlanNode compaction: aggressiveRetry=" + aggressiveRetry
                + " compacted=" + result.compacted()
                + " beforeTokens=" + result.estimatedTokensBefore()
                + " afterTokens=" + result.estimatedTokensAfter()
                + " budgetTokens=" + result.budgetTokens()
                + " passes=" + result.passes());
        return result.messages();
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

    private Throwable unwrapThrowable(Throwable throwable) {
        if (throwable instanceof java.util.concurrent.CompletionException && throwable.getCause() != null) {
            return unwrapThrowable(throwable.getCause());
        }
        if (throwable instanceof java.util.concurrent.ExecutionException && throwable.getCause() != null) {
            return unwrapThrowable(throwable.getCause());
        }
        return throwable;
    }

    private RunTree beginPlanTrace(List<ChatMessage> messages) {
        if (tracer == null || !tracer.isEnabled()) {
            return null;
        }
        String desc = "messages=" + messages.size();
        return tracer.beginLlmRun(tracer.getCurrentRoot(), "plan", desc);
    }

    private void endPlanTrace(RunTree run, AiMessage aiMessage) {
        if (tracer == null || run == null) {
            return;
        }
        int toolCalls = aiMessage != null && aiMessage.toolExecutionRequests() != null
                ? aiMessage.toolExecutionRequests().size() : 0;
        int textLen = aiMessage != null && aiMessage.text() != null ? aiMessage.text().length() : 0;
        tracer.endRun(run, LangSmithTracer.outputsOf(
                "text_length", String.valueOf(textLen),
                "tool_calls", String.valueOf(toolCalls)));
    }

    private void endPlanTraceWithError(RunTree run, Throwable error) {
        if (tracer == null || run == null) {
            return;
        }
        tracer.endRunWithError(run, error.getMessage());
    }

    private Map<String, Object> buildUpdate(AiMessage aiMessage) {
        Map<String, Object> update = new HashMap<>();
        update.put(CopilotDeepState.MESSAGES, aiMessage);
        if (aiMessage != null && !aiMessage.hasToolExecutionRequests()) {
            String text = aiMessage.text() != null ? aiMessage.text() : "";
            update.put(CopilotDeepState.FINAL_RESPONSE, text);
        }
        return update;
    }

    private void logAiMessage(AiMessage aiMessage) {
        ghidra.util.Msg.debug(this,
            "PlanNode aiTextLen=" + (aiMessage != null && aiMessage.text() != null ? aiMessage.text().length() : -1)
            + " toolCalls=" + (aiMessage != null && aiMessage.toolExecutionRequests() != null ? aiMessage.toolExecutionRequests().size() : 0));
    }

    private String orchestrationInstructions() {
        return CopilotPrompts.PLANNER_ORCHESTRATION_PROMPT;
    }
}
