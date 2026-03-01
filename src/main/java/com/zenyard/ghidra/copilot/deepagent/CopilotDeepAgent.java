package com.zenyard.ghidra.copilot.deepagent;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.bsc.async.AsyncGenerator;
import org.bsc.langgraph4j.CompiledGraph;
import org.bsc.langgraph4j.GraphStateException;
import org.bsc.langgraph4j.NodeOutput;
import org.bsc.langgraph4j.RunnableConfig;
import org.bsc.langgraph4j.langchain4j.tool.LC4jToolService;

import com.zenyard.ghidra.copilot.CopilotStreamHandler;
import com.zenyard.ghidra.copilot.skills.SkillsService;

import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.StreamingChatModel;


/**
 * Deep agent graph builder and runner for Copilot.
 */
public class CopilotDeepAgent {
    private final CompiledGraph<CopilotDeepState> graph;
    private final ResponseNode responseNode;
    private final DeepAgentMemoryAdapter memoryAdapter;
    private final CopilotDeepAgentConfig deepAgentConfig;
    private final LangSmithTracer tracer;

    public CopilotDeepAgent(
            ChatModel planningModel,
            StreamingChatModel streamingChatModel,
            List<Object> tools,
            CopilotStreamHandler streamHandler,
            DeepAgentMemoryAdapter memoryAdapter,
            String systemPrompt,
            boolean sanitizeToolMessages) throws GraphStateException {
        this(
            planningModel,
            streamingChatModel,
            tools,
            streamHandler,
            memoryAdapter,
            null,
            systemPrompt,
            sanitizeToolMessages,
            CopilotDeepAgentConfig.defaults()
        );
    }

    public CopilotDeepAgent(
            ChatModel planningModel,
            StreamingChatModel streamingChatModel,
            List<Object> tools,
            CopilotStreamHandler streamHandler,
            DeepAgentMemoryAdapter memoryAdapter,
            String systemPrompt,
            boolean sanitizeToolMessages,
            CopilotDeepAgentConfig config) throws GraphStateException {
        this(
            planningModel,
            streamingChatModel,
            tools,
            streamHandler,
            memoryAdapter,
            null,
            systemPrompt,
            sanitizeToolMessages,
            config
        );
    }

    public CopilotDeepAgent(
            ChatModel planningModel,
            StreamingChatModel streamingChatModel,
            List<Object> tools,
            CopilotStreamHandler streamHandler,
            DeepAgentMemoryAdapter memoryAdapter,
            SkillsService skillsService,
            String systemPrompt,
            boolean sanitizeToolMessages,
            CopilotDeepAgentConfig config) throws GraphStateException {
        this(planningModel, streamingChatModel, tools, streamHandler,
                memoryAdapter, skillsService, systemPrompt,
                sanitizeToolMessages, config, null);
    }

    public CopilotDeepAgent(
            ChatModel planningModel,
            StreamingChatModel streamingChatModel,
            List<Object> tools,
            CopilotStreamHandler streamHandler,
            DeepAgentMemoryAdapter memoryAdapter,
            SkillsService skillsService,
            String systemPrompt,
            boolean sanitizeToolMessages,
            CopilotDeepAgentConfig config,
            LangSmithTracer tracer) throws GraphStateException {
        CopilotDeepAgentConfig resolvedConfig = config != null ? config : CopilotDeepAgentConfig.defaults();

        this.tracer = tracer;

        LC4jToolService toolService = LC4jToolService.builder()
            .toolsFromObject(tools.toArray())
            .build();

        PlanNode planNode = new PlanNode(
            planningModel,
            streamingChatModel,
            streamHandler,
            toolService.toolSpecifications(),
            systemPrompt,
            sanitizeToolMessages,
            tracer
        );
        ToolNode toolNode = new ToolNode(
            toolService,
            resolvedConfig.returnDirectTools(),
            resolvedConfig.parallelToolExecution(),
            resolvedConfig.parallelToolMaxConcurrency(),
            resolvedConfig.toolCallTimeoutMs(),
            tracer
        );
        ResponseNode responseNode = new ResponseNode(
            planningModel,
            streamingChatModel,
            streamHandler,
            List.of(),
            systemPrompt,
            sanitizeToolMessages,
            resolvedConfig.responseStreamingTimeoutMs(),
            tracer);

        this.responseNode = responseNode;
        this.memoryAdapter = memoryAdapter;
        this.deepAgentConfig = resolvedConfig;
        this.graph = new CopilotOrchestrator().build(
            planNode,
            toolNode,
            responseNode,
            resolvedConfig,
            skillsService
        );
    }

    public LangSmithTracer getTracer() {
        return tracer;
    }

    public AsyncGenerator<NodeOutput<CopilotDeepState>> stream(String userMessage) {
        return stream(userMessage, Map.of());
    }

    public AsyncGenerator<NodeOutput<CopilotDeepState>> stream(
            String userMessage,
            Map<String, String> artifacts) {
        if (tracer != null && tracer.isEnabled()) {
            tracer.beginTrace("copilot-turn", userMessage);
        }

        Map<String, Object> initState = new java.util.HashMap<>();
        List<dev.langchain4j.data.message.ChatMessage> messages = new ArrayList<>();
        if (memoryAdapter != null) {
            messages.addAll(memoryAdapter.getHistory());
        }
        messages.add(UserMessage.from(userMessage));
        initState.put(CopilotDeepState.MESSAGES, messages);
        if (artifacts != null && !artifacts.isEmpty()) {
            initState.put(CopilotDeepState.ARTIFACTS, artifacts);
        }
        RunnableConfig config = RunnableConfig.builder()
            .threadId(deepAgentConfig.threadId())
            .build();
        return graph.stream(initState, config);
    }

    /**
     * End the current LangSmith trace with the final response text.
     * Should be called by the controller after stream completes.
     */
    public void endTrace(String finalResponse) {
        if (tracer != null && tracer.isEnabled()) {
            tracer.endTrace(tracer.getCurrentRoot(), finalResponse);
        }
    }

    public Map<String, Object> buildFinalResponse(CopilotDeepState state) {
        return responseNode != null && state != null
            ? responseNode.buildFinalResponse(state)
            : Map.of();
    }
}
