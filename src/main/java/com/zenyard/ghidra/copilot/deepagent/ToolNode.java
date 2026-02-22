package com.zenyard.ghidra.copilot.deepagent;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Objects;
import java.util.stream.Collectors;

import org.bsc.langgraph4j.action.AsyncNodeActionWithConfig;
import org.bsc.langgraph4j.langchain4j.tool.LC4jToolService;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.ToolExecutionResultMessage;
import dev.langchain4j.invocation.InvocationContext;
import dev.langchain4j.invocation.InvocationParameters;
import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.langsmith.RunTree;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Tool execution node: runs LangChain4j tool calls and returns results to state.
 */
public class ToolNode implements AsyncNodeActionWithConfig<CopilotDeepState> {

    private final LC4jToolService toolService;
    private final Set<String> returnDirectTools;
    private final boolean parallelToolExecution;
    private final int parallelToolMaxConcurrency;
    private final long toolCallTimeoutMs;
    private final LangSmithTracer tracer;
    private static final int TOOL_ARG_LOG_LIMIT = 2000;
    private static final int REPEATED_TOOL_BATCH_LIMIT = 3;
    private static final int TOOL_SIGNATURE_MAX_NAMES = 64;
    private static final int TOOL_SIGNATURE_MAX_NAME_LEN = 64;

    public ToolNode(LC4jToolService toolService) {
        this(toolService, Set.of(), false, 4, 60_000L, null);
    }

    public ToolNode(LC4jToolService toolService, Set<String> returnDirectTools) {
        this(toolService, returnDirectTools, false, 4, 60_000L, null);
    }

    public ToolNode(
            LC4jToolService toolService,
            Set<String> returnDirectTools,
            boolean parallelToolExecution,
            int parallelToolMaxConcurrency,
            long toolCallTimeoutMs) {
        this(toolService, returnDirectTools, parallelToolExecution,
                parallelToolMaxConcurrency, toolCallTimeoutMs, null);
    }

    public ToolNode(
            LC4jToolService toolService,
            Set<String> returnDirectTools,
            boolean parallelToolExecution,
            int parallelToolMaxConcurrency,
            long toolCallTimeoutMs,
            LangSmithTracer tracer) {
        this.toolService = toolService;
        this.returnDirectTools = new LinkedHashSet<>(returnDirectTools != null ? returnDirectTools : Set.of());
        this.parallelToolExecution = parallelToolExecution;
        this.parallelToolMaxConcurrency = Math.max(1, parallelToolMaxConcurrency);
        this.toolCallTimeoutMs = toolCallTimeoutMs > 0 ? toolCallTimeoutMs : 60_000L;
        this.tracer = tracer;
    }

    @Override
    public CompletableFuture<Map<String, Object>> apply(CopilotDeepState state, org.bsc.langgraph4j.RunnableConfig config) {
        ChatMessage lastMessage = state.lastMessage().orElse(null);
        if (!(lastMessage instanceof AiMessage aiMessage) || !aiMessage.hasToolExecutionRequests()) {
            return CompletableFuture.completedFuture(Map.of());
        }

        InvocationContext context = InvocationContext.builder()
            .invocationParameters(InvocationParameters.from(state.data()))
            .build();

        List<String> toolNames = aiMessage.toolExecutionRequests()
            .stream()
            .map(request -> request.name())
            .collect(Collectors.toList());
        String toolBatchSignature = buildToolBatchSignature(toolNames);
        String previousSignature = state.lastToolBatchSignature();
        int repeatCount = toolBatchSignature.equals(previousSignature)
            ? state.sameToolBatchCount() + 1
            : 1;
        boolean repeatedTodosOnly = "write_todos".equals(toolBatchSignature) && repeatCount >= 2;
        boolean repeatedToolBatch = repeatCount >= REPEATED_TOOL_BATCH_LIMIT;

        Map<String, RunTree> toolTraceRuns = new HashMap<>();
        aiMessage.toolExecutionRequests().forEach(request -> {
            String args = truncateToolArguments(request.arguments());
            ghidra.util.Msg.info(this, "Tool call: " + request.name() + " args=" + args);
            if (tracer != null && tracer.isEnabled()) {
                RunTree run = tracer.beginToolRun(tracer.getCurrentRoot(), request.name(), args);
                if (run != null) {
                    toolTraceRuns.put(request.id(), run);
                }
            }
        });

        CompletableFuture<org.bsc.langgraph4j.action.Command> execution =
            executeToolRequests(aiMessage.toolExecutionRequests(), context);

        return execution
            .thenApply(command -> {
                Map<String, Object> update = new HashMap<>(command.update());
                update.put(CopilotDeepState.TOOL_EVENTS, toolNames);
                boolean forceReturnDirect = repeatedTodosOnly || repeatedToolBatch;
                if (forceReturnDirect) {
                    ghidra.util.Msg.warn(this,
                        "Tool loop guard triggered for signature '" + toolBatchSignature
                            + "' (repeatCount=" + repeatCount + ")");
                }
                update.put(CopilotDeepState.RETURN_DIRECT,
                    toolNames.stream().anyMatch(returnDirectTools::contains) || forceReturnDirect);
                update.put(CopilotDeepState.JUMP_TO, "");
                update.put(CopilotDeepState.LAST_TOOL_BATCH_SIGNATURE, toolBatchSignature);
                update.put(CopilotDeepState.SAME_TOOL_BATCH_COUNT, repeatCount);

                endToolTraceRuns(toolTraceRuns, update);
                return update;
            })
            .exceptionally(error -> {
                Throwable cause = error.getCause() != null ? error.getCause() : error;
                String errorText = "Tool execution failed: " + cause.getMessage();
                ghidra.util.Msg.error(this, errorText, cause);

                toolTraceRuns.values().forEach(run ->
                        tracer.endRunWithError(run, errorText));

                List<Object> errorMessages = aiMessage.toolExecutionRequests().stream()
                    .map(req -> (Object) new ToolExecutionResultMessage(req.id(), req.name(), errorText))
                    .collect(Collectors.toList());

                Map<String, Object> update = new HashMap<>();
                update.put(CopilotDeepState.MESSAGES, errorMessages);
                update.put(CopilotDeepState.TOOL_EVENTS, toolNames);
                update.put(CopilotDeepState.RETURN_DIRECT, Boolean.FALSE);
                update.put(CopilotDeepState.JUMP_TO, "");
                update.put(CopilotDeepState.LAST_TOOL_BATCH_SIGNATURE, toolBatchSignature);
                update.put(CopilotDeepState.SAME_TOOL_BATCH_COUNT, repeatCount);
                return update;
            });
    }

    private CompletableFuture<org.bsc.langgraph4j.action.Command> executeToolRequests(
            List<ToolExecutionRequest> requests,
            InvocationContext context) {
        if (!parallelToolExecution || requests.size() <= 1) {
            long batchTimeout = toolCallTimeoutMs * Math.max(1, requests.size());
            return toolService.execute(requests, context, CopilotDeepState.MESSAGES)
                .orTimeout(batchTimeout, TimeUnit.MILLISECONDS)
                .exceptionally(error -> {
                    Throwable cause = error instanceof java.util.concurrent.CompletionException
                        ? error.getCause() : error;
                    if (cause instanceof TimeoutException) {
                        ghidra.util.Msg.warn(this,
                            "Tool batch timed out after " + (batchTimeout / 1000) + "s for "
                            + requests.size() + " tool call(s)");
                    }
                    throw (error instanceof RuntimeException)
                        ? (RuntimeException) error
                        : new RuntimeException(error);
                });
        }

        final int concurrency = Math.max(1, Math.min(parallelToolMaxConcurrency, requests.size()));
        final ExecutorService executor = Executors.newFixedThreadPool(concurrency);

        List<CompletableFuture<org.bsc.langgraph4j.action.Command>> futures = requests.stream()
            .map(request -> CompletableFuture.supplyAsync(
                () -> toolService.execute(List.of(request), context, CopilotDeepState.MESSAGES).join(),
                executor)
                .orTimeout(toolCallTimeoutMs, TimeUnit.MILLISECONDS)
                .exceptionally(error -> {
                    Throwable cause = error instanceof java.util.concurrent.CompletionException
                        ? error.getCause() : error;
                    String errorMsg;
                    if (cause instanceof TimeoutException) {
                        errorMsg = "Tool '" + request.name() + "' timed out after "
                            + (toolCallTimeoutMs / 1000) + " seconds";
                        ghidra.util.Msg.warn(this, errorMsg);
                    } else {
                        errorMsg = "Tool '" + request.name() + "' failed: " + cause.getMessage();
                    }
                    Map<String, Object> errorUpdate = new HashMap<>();
                    errorUpdate.put(CopilotDeepState.MESSAGES,
                        List.of(new ToolExecutionResultMessage(
                            request.id(), request.name(), "Error: " + errorMsg)));
                    return new org.bsc.langgraph4j.action.Command(null, errorUpdate);
                }))
            .collect(Collectors.toList());

        return CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new))
            .thenApply(ignored -> {
                List<Object> toolMessages = new ArrayList<>();
                Map<String, Object> mergedUpdate = new HashMap<>();
                String gotoNode = null;

                for (CompletableFuture<org.bsc.langgraph4j.action.Command> future : futures) {
                    org.bsc.langgraph4j.action.Command command = future.join();
                    if (command.gotoNodeSafe().isPresent()) {
                        if (gotoNode != null && !Objects.equals(gotoNode, command.gotoNode())) {
                            throw new IllegalStateException(
                                "Multiple nodes target provided! tried to set "
                                    + command.gotoNode() + " when " + gotoNode + " was already present");
                        }
                        gotoNode = command.gotoNode();
                    }
                    for (Map.Entry<String, Object> entry : command.update().entrySet()) {
                        if (CopilotDeepState.MESSAGES.equals(entry.getKey()) && entry.getValue() instanceof List<?>) {
                            toolMessages.addAll((List<?>) entry.getValue());
                        } else {
                            mergedUpdate.put(entry.getKey(), entry.getValue());
                        }
                    }
                }
                mergedUpdate.put(CopilotDeepState.MESSAGES, toolMessages);
                return new org.bsc.langgraph4j.action.Command(gotoNode, mergedUpdate);
            })
            .whenComplete((ignored, throwable) -> executor.shutdown());
    }

    private void endToolTraceRuns(Map<String, RunTree> toolTraceRuns, Map<String, Object> update) {
        if (tracer == null || toolTraceRuns.isEmpty()) {
            return;
        }
        Object msgs = update.get(CopilotDeepState.MESSAGES);
        if (msgs instanceof List<?> messageList) {
            for (Object msg : messageList) {
                if (msg instanceof ToolExecutionResultMessage resultMsg) {
                    RunTree run = toolTraceRuns.remove(resultMsg.id());
                    if (run != null) {
                        String text = resultMsg.text();
                        String truncated = text != null && text.length() > 2000
                                ? text.substring(0, 2000) + "..." : text;
                        tracer.endRun(run, LangSmithTracer.outputsOf("result", truncated));
                    }
                }
            }
        }
        toolTraceRuns.values().forEach(run ->
                tracer.endRun(run, LangSmithTracer.outputsOf("result", "completed")));
    }

    private static String truncateToolArguments(String arguments) {
        if (arguments == null) {
            return "";
        }
        if (arguments.length() <= TOOL_ARG_LOG_LIMIT) {
            return arguments;
        }
        return arguments.substring(0, TOOL_ARG_LOG_LIMIT)
            + "...(truncated, len=" + arguments.length() + ")";
    }

    private static String buildToolBatchSignature(List<String> toolNames) {
        if (toolNames == null || toolNames.isEmpty()) {
            return "";
        }
        StringBuilder signature = new StringBuilder();
        int count = Math.min(toolNames.size(), TOOL_SIGNATURE_MAX_NAMES);
        for (int i = 0; i < count; i++) {
            if (i > 0) {
                signature.append(',');
            }
            String name = toolNames.get(i);
            if (name == null) {
                name = "";
            }
            if (name.length() > TOOL_SIGNATURE_MAX_NAME_LEN) {
                name = name.substring(0, TOOL_SIGNATURE_MAX_NAME_LEN);
            }
            signature.append(name);
        }
        if (toolNames.size() > TOOL_SIGNATURE_MAX_NAMES) {
            signature.append(",+").append(toolNames.size() - TOOL_SIGNATURE_MAX_NAMES).append("more");
        }
        return signature.toString();
    }
}
