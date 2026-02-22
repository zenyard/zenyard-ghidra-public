package com.zenyard.ghidra.copilot.deepagent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import org.bsc.async.AsyncGenerator;
import org.bsc.langgraph4j.CompileConfig;
import org.bsc.langgraph4j.CompiledGraph;
import org.bsc.langgraph4j.GraphInput;
import org.bsc.langgraph4j.GraphStateException;
import org.bsc.langgraph4j.NodeOutput;
import org.bsc.langgraph4j.RunnableConfig;
import org.bsc.langgraph4j.langchain4j.serializer.std.LC4jStateSerializer;
import org.bsc.langgraph4j.langchain4j.tool.LC4jToolResponseBuilder;
import org.bsc.langgraph4j.agentexecutor.AgentExecutor;
import org.bsc.langgraph4j.streaming.StreamingOutput;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.invocation.InvocationParameters;
import dev.langchain4j.langsmith.RunTree;
import dev.langchain4j.model.chat.StreamingChatModel;
import dev.langchain4j.service.tool.ToolExecutor;

/**
 * Builds the "task" tool for invoking sub-agents.
 */
public class CopilotTaskToolBuilder {

    /**
     * Callback for sub-agent lifecycle events so the UI can show progress.
     */
    public interface SubAgentProgressListener {
        void onSubAgentStart(String agentType, String description);
        void onSubAgentEnd(String agentType, boolean success);
        default void onSubAgentToken(String agentType, String token) {}
    }

    private StreamingChatModel streamingChatModel;
    private List<SubAgent> subAgents = List.of();
    private Map<ToolSpecification, ToolExecutor> toolMap = Map.of();
    private List<Object> toolObjects = List.of();
    private CompileConfig compileConfig = CompileConfig.builder().build();
    private long subAgentTimeoutMs = 180_000L;
    private int subAgentRecursionLimit = 50;
    private LangSmithTracer tracer;
    private SubAgentProgressListener progressListener;

    public CopilotTaskToolBuilder streamingChatModel(StreamingChatModel model) {
        this.streamingChatModel = Objects.requireNonNull(model, "model cannot be null");
        return this;
    }

    public CopilotTaskToolBuilder subAgents(List<SubAgent> subAgents) {
        this.subAgents = List.copyOf(Objects.requireNonNull(subAgents, "subAgents cannot be null"));
        return this;
    }

    public CopilotTaskToolBuilder toolMap(Map<ToolSpecification, ToolExecutor> toolMap) {
        this.toolMap = Map.copyOf(Objects.requireNonNull(toolMap, "toolMap cannot be null"));
        return this;
    }

    /**
     * Set raw tool objects (annotated with @Tool) to be shared with subagents.
     * These are resolved via LC4jToolService internally.
     */
    public CopilotTaskToolBuilder toolObjects(List<Object> toolObjects) {
        this.toolObjects = List.copyOf(Objects.requireNonNull(toolObjects, "toolObjects cannot be null"));
        return this;
    }

    public CopilotTaskToolBuilder compileConfig(CompileConfig compileConfig) {
        this.compileConfig = Objects.requireNonNull(compileConfig, "compileConfig cannot be null");
        return this;
    }

    public CopilotTaskToolBuilder subAgentTimeoutMs(long subAgentTimeoutMs) {
        this.subAgentTimeoutMs = Math.max(1000L, subAgentTimeoutMs);
        return this;
    }

    public CopilotTaskToolBuilder subAgentRecursionLimit(int subAgentRecursionLimit) {
        this.subAgentRecursionLimit = Math.max(1, subAgentRecursionLimit);
        return this;
    }

    public CopilotTaskToolBuilder tracer(LangSmithTracer tracer) {
        this.tracer = tracer;
        return this;
    }

    public CopilotTaskToolBuilder progressListener(SubAgentProgressListener listener) {
        this.progressListener = listener;
        return this;
    }

    public Object build() throws GraphStateException {
        if (streamingChatModel == null) {
            throw new IllegalStateException("streamingChatModel must be set");
        }
        if (subAgents == null || subAgents.isEmpty()) {
            throw new IllegalStateException("subAgents must be provided");
        }
        return new TaskTool(buildSubAgentGraphs(), subAgentTimeoutMs, tracer, progressListener);
    }

    private Map<String, CompiledGraph<CopilotDeepAgentState>> buildSubAgentGraphs() throws GraphStateException {
        Map<String, CompiledGraph<CopilotDeepAgentState>> graphs = new HashMap<>();
        Map<String, Map.Entry<ToolSpecification, ToolExecutor>> toolByName = toolMap.entrySet().stream()
            .collect(Collectors.toMap(entry -> entry.getKey().name(), entry -> entry));

        for (SubAgent subAgent : subAgents) {
            AgentExecutor.Builder builder = AgentExecutor.builder()
                .chatModel(streamingChatModel)
                .stateSerializer(new LC4jStateSerializer<>(CopilotDeepAgentState::new))
                .systemMessage(SystemMessage.from(subAgent.prompt()));

            if (toolObjects != null && !toolObjects.isEmpty()) {
                builder.toolsFromObject(toolObjects.toArray());
            }

            List<Map.Entry<ToolSpecification, ToolExecutor>> selected = resolveTools(subAgent, toolByName);
            for (Map.Entry<ToolSpecification, ToolExecutor> entry : selected) {
                builder.tool(entry.getKey(), entry.getValue());
            }

            CompileConfig subAgentCompileConfig = CompileConfig.builder()
                .recursionLimit(subAgentRecursionLimit)
                .build();

            @SuppressWarnings("unchecked")
            CompiledGraph<CopilotDeepAgentState> graph =
                (CompiledGraph<CopilotDeepAgentState>) (CompiledGraph<?>) builder.build().compile(subAgentCompileConfig);
            graphs.put(subAgent.name(), graph);
        }
        return graphs;
    }

    private List<Map.Entry<ToolSpecification, ToolExecutor>> resolveTools(
            SubAgent subAgent,
            Map<String, Map.Entry<ToolSpecification, ToolExecutor>> toolByName) {
        if (subAgent.tools() == null || subAgent.tools().isEmpty()) {
            return new ArrayList<>(toolByName.values());
        }
        List<Map.Entry<ToolSpecification, ToolExecutor>> selected = new ArrayList<>();
        for (String toolName : subAgent.tools()) {
            Map.Entry<ToolSpecification, ToolExecutor> entry = toolByName.get(toolName);
            if (entry != null) {
                selected.add(entry);
            }
        }
        return selected;
    }

    public record SubAgent(String name, String description, String prompt, List<String> tools) {
        public SubAgent {
            Objects.requireNonNull(name, "name cannot be null");
            Objects.requireNonNull(description, "description cannot be null");
            Objects.requireNonNull(prompt, "prompt cannot be null");
        }
    }

    private static class TaskTool {
        private final Map<String, CompiledGraph<CopilotDeepAgentState>> graphs;
        private final long timeoutMs;
        private final LangSmithTracer tracer;
        private final SubAgentProgressListener progressListener;

        private static final java.util.Set<String> EXCLUDED_STATE_KEYS = java.util.Set.of(
            "messages", "todos", "active_todo", "skills_prompt",
            "final_response", "tool_events", "jump_to", "return_direct",
            "completed_todos", "failed_todos"
        );

        private TaskTool(Map<String, CompiledGraph<CopilotDeepAgentState>> graphs,
                         long timeoutMs, LangSmithTracer tracer,
                         SubAgentProgressListener progressListener) {
            this.graphs = graphs;
            this.timeoutMs = timeoutMs;
            this.tracer = tracer;
            this.progressListener = progressListener;
        }

        @Tool("Launch a sub-agent to handle a complex task. Provide description and sub_agent_type.")
        public String task(
                @P("description") String description,
                @P("sub_agent_type") String subAgentType,
                InvocationParameters context) {
            if (description == null || description.isBlank()) {
                return "Error: description is required.";
            }
            if (subAgentType == null || subAgentType.isBlank()) {
                return "Error: sub_agent_type is required.";
            }
            CompiledGraph<CopilotDeepAgentState> graph = graphs.get(subAgentType);
            if (graph == null) {
                return "Error: Agent '" + subAgentType + "' not found. Available agents: "
                    + String.join(", ", graphs.keySet());
            }

            RunTree traceRun = null;
            if (tracer != null && tracer.isEnabled()) {
                traceRun = tracer.beginChainRun(tracer.getCurrentRoot(),
                        "subagent:" + subAgentType, description);
            }

            notifyStart(subAgentType, description);

            Map<String, Object> inputState = new HashMap<>();
            if (context != null) {
                context.asMap().forEach((key, value) -> {
                    if (!EXCLUDED_STATE_KEYS.contains(key)) {
                        inputState.put(key, value);
                    }
                });
            }
            inputState.put("messages", List.of(UserMessage.from(description)));

            CopilotDeepAgentState lastState = null;
            try {
                lastState = CompletableFuture.supplyAsync(() -> {
                    AsyncGenerator<NodeOutput<CopilotDeepAgentState>> generator =
                        graph.stream(GraphInput.args(inputState), RunnableConfig.builder().build());
                    CopilotDeepAgentState finalState = null;
                    for (var output : (Iterable<NodeOutput<CopilotDeepAgentState>>) generator.stream()::iterator) {
                        if (output instanceof StreamingOutput<CopilotDeepAgentState> streaming) {
                            String chunk = streaming.chunk();
                            if (chunk != null && !chunk.isEmpty()) {
                                notifyToken(subAgentType, chunk);
                            }
                        } else {
                            finalState = output.state();
                        }
                    }
                    return finalState;
                }).get(timeoutMs, TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                notifyEnd(subAgentType, false);
                ghidra.util.Msg.warn(this,
                    "Sub-agent '" + subAgentType + "' timed out after " + timeoutMs + "ms");
                String errorMsg = "Error: Sub-agent '" + subAgentType + "' timed out after "
                    + (timeoutMs / 1000) + " seconds. The task may be too complex for a single sub-agent call. "
                    + "Try breaking it into smaller, more focused tasks.";
                endSubagentTrace(traceRun, errorMsg, true);
                return errorMsg;
            } catch (InterruptedException e) {
                notifyEnd(subAgentType, false);
                Thread.currentThread().interrupt();
                String errorMsg = "Error: Sub-agent '" + subAgentType + "' was interrupted.";
                endSubagentTrace(traceRun, errorMsg, true);
                return errorMsg;
            } catch (java.util.concurrent.ExecutionException e) {
                notifyEnd(subAgentType, false);
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                if (isMaxIterationsReached(cause)) {
                    String gracefulMsg = "Sub-agent '" + subAgentType + "' stopped after reaching the maximum "
                        + "iteration limit. Partial progress may be available. Try narrowing the task scope or "
                        + "splitting it into smaller focused calls.";
                    ghidra.util.Msg.warn(this, gracefulMsg);
                    endSubagentTrace(traceRun, gracefulMsg, true);
                    return gracefulMsg;
                }
                ghidra.util.Msg.error(this,
                    "Sub-agent '" + subAgentType + "' failed: " + cause.getMessage(), cause);
                String errorMsg = "Error: Sub-agent '" + subAgentType + "' failed: " + cause.getMessage();
                endSubagentTrace(traceRun, errorMsg, true);
                return errorMsg;
            }

            notifyEnd(subAgentType, true);

            if (lastState == null) {
                String errorMsg = "Error: Sub-agent did not return a result.";
                endSubagentTrace(traceRun, errorMsg, true);
                return errorMsg;
            }
            Map<String, String> files = lastState.files();
            Map<String, String> artifacts = lastState.artifacts();
            String response = lastState.lastMessage()
                .map(msg -> msg instanceof dev.langchain4j.data.message.AiMessage ai ? ai.text() : msg.toString())
                .orElse("Task completed");

            endSubagentTrace(traceRun, response != null ? response : "Task completed", false);

            return LC4jToolResponseBuilder.of(context)
                .update(Map.of(
                    CopilotDeepAgentState.FILES, files,
                    CopilotDeepAgentState.ARTIFACTS, artifacts))
                .buildAndReturn(response != null ? response : "Task completed");
        }

        private void notifyStart(String agentType, String description) {
            if (progressListener == null) {
                return;
            }
            try {
                progressListener.onSubAgentStart(agentType, description);
            } catch (Exception ignored) {
            }
        }

        private void notifyEnd(String agentType, boolean success) {
            if (progressListener == null) {
                return;
            }
            try {
                progressListener.onSubAgentEnd(agentType, success);
            } catch (Exception ignored) {
            }
        }

        private void notifyToken(String agentType, String token) {
            if (progressListener == null) {
                return;
            }
            try {
                progressListener.onSubAgentToken(agentType, token);
            } catch (Exception ignored) {
            }
        }

        private void endSubagentTrace(RunTree run, String result, boolean isError) {
            if (tracer == null || run == null) {
                return;
            }
            if (isError) {
                tracer.endRunWithError(run, result);
            } else {
                tracer.endRun(run, LangSmithTracer.outputsOf("output", result));
            }
        }

        private boolean isMaxIterationsReached(Throwable error) {
            if (!(error instanceof IllegalStateException)) {
                return false;
            }
            String message = error.getMessage();
            if (message == null) {
                return false;
            }
            return message.contains("Maximum number of iterations");
        }
    }
}
