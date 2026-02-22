package com.zenyard.ghidra.copilot.deepagent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.bsc.langgraph4j.RunnableConfig;
import org.bsc.langgraph4j.action.AsyncNodeActionWithConfig;

import com.zenyard.ghidra.copilot.CopilotPrompts;
import com.zenyard.ghidra.copilot.CopilotStreamHandler;

import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.langsmith.RunTree;
import dev.langchain4j.langsmith.gen.model.Outputs;
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
    private final LangSmithTracer tracer;
    private static final long STREAMING_TIMEOUT_MS = 120_000L;

    public PlanNode(
            ChatModel chatModel,
            List<ToolSpecification> toolSpecifications,
            String systemPrompt,
            boolean sanitizeToolMessages) {
        this(chatModel, null, null, toolSpecifications, systemPrompt, sanitizeToolMessages, null);
    }

    public PlanNode(
            ChatModel chatModel,
            StreamingChatModel streamingChatModel,
            CopilotStreamHandler streamHandler,
            List<ToolSpecification> toolSpecifications,
            String systemPrompt,
            boolean sanitizeToolMessages,
            LangSmithTracer tracer) {
        this.chatModel = chatModel;
        this.streamingChatModel = streamingChatModel;
        this.streamHandler = streamHandler;
        this.toolSpecifications = toolSpecifications;
        this.systemPrompt = systemPrompt;
        this.sanitizeToolMessages = sanitizeToolMessages;
        this.tracer = tracer;
    }

    @Override
    public CompletableFuture<Map<String, Object>> apply(CopilotDeepState state, RunnableConfig config) {
        String skillsSection = state.skillsPrompt().orElse("");
        String resolvedSystemPrompt = systemPrompt + "\n\n" + skillsSection + "\n\n" + orchestrationInstructions();

        List<ChatMessage> rawMessages = new ArrayList<>();
        rawMessages.add(SystemMessage.from(resolvedSystemPrompt));
        rawMessages.addAll(state.messages());
        List<ChatMessage> patchedMessages = MessageSanitizer.patchDanglingToolCalls(rawMessages);
        MessageSanitizer.SanitizeResult sanitizeResult = MessageSanitizer.sanitizeMessages(patchedMessages, sanitizeToolMessages);
        List<ChatMessage> messages = sanitizeResult.messages();
        ghidra.util.Msg.debug(this, "PlanNode input messages=" + messages.size());

        ChatRequestParameters parameters = ChatRequestParameters.builder()
            .toolSpecifications(toolSpecifications)
            .build();

        if (streamingChatModel != null && streamHandler != null) {
            return streamPlan(messages, parameters);
        }
        return CompletableFuture.completedFuture(syncPlan(messages, parameters));
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
                streamHandler.onPlanningToken(partialResponse);
            }

            @Override
            public void onCompleteResponse(ChatResponse response) {
                streamHandler.endPlanningPhase();
                AiMessage aiMessage = response.aiMessage();
                logAiMessage(aiMessage);
                endPlanTrace(traceRun, aiMessage);
                future.complete(buildUpdate(aiMessage));
            }

            @Override
            public void onError(Throwable error) {
                streamHandler.endPlanningPhase();
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
