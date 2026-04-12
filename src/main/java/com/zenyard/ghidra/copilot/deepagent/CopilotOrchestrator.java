package com.zenyard.ghidra.copilot.deepagent;

import java.util.HashMap;
import java.util.Map;

import ghidra.util.Msg;

import org.bsc.langgraph4j.CompiledGraph;
import org.bsc.langgraph4j.CompileConfig;
import org.bsc.langgraph4j.GraphStateException;
import org.bsc.langgraph4j.StateGraph;
import org.bsc.langgraph4j.action.EdgeAction;
import org.bsc.langgraph4j.action.NodeAction;
import org.bsc.langgraph4j.langchain4j.serializer.std.LC4jStateSerializer;
import org.bsc.langgraph4j.utils.EdgeMappings;

import com.zenyard.ghidra.copilot.CopilotPrompts;
import com.zenyard.ghidra.copilot.skills.SkillsService;

import static org.bsc.langgraph4j.StateGraph.END;
import static org.bsc.langgraph4j.StateGraph.START;
import static org.bsc.langgraph4j.action.AsyncEdgeAction.edge_async;
import static org.bsc.langgraph4j.action.AsyncNodeAction.node_async;

/**
 * Orchestrator graph that routes between planner, tools, subagents, and response.
 */
public class CopilotOrchestrator {
    private static final String BEFORE_AGENT_NODE = "before_agent";
    private static final String BEFORE_MODEL_NODE = "before_model";
    private static final String MODEL_NODE = "model";
    private static final String AFTER_MODEL_NODE = "after_model";
    private static final String TOOLS_NODE = "tools";
    private static final String AFTER_AGENT_NODE = "after_agent";

    public CompiledGraph<CopilotDeepState> build(
            PlanNode planNode,
            ToolNode toolNode,
            ResponseNode responseNode,
            CopilotDeepAgentConfig deepAgentConfig,
            SkillsService skillsService) throws GraphStateException {

        EdgeAction<CopilotDeepState> routeFromModel = state -> {
            String jump = state.jumpTo().orElse("");
            if ("model".equalsIgnoreCase(jump)) {
                return "model";
            }
            if ("tools".equalsIgnoreCase(jump)) {
                return "tools";
            }
            if ("end".equalsIgnoreCase(jump)) {
                return "respond";
            }

            var last = state.lastMessage().orElse(null);
            if (last instanceof dev.langchain4j.data.message.AiMessage aiMessage
                    && aiMessage.toolExecutionRequests() != null
                    && !aiMessage.toolExecutionRequests().isEmpty()) {
                return "tools";
            }
            return "respond";
        };

        EdgeAction<CopilotDeepState> routeFromTools = state -> {
            if (state.returnDirect()) {
                return "respond";
            }
            return "model";
        };

        StateGraph<CopilotDeepState> graph = new StateGraph<>(
            CopilotDeepState.SCHEMA,
            new LC4jStateSerializer<>(CopilotDeepState::new))
            .addNode(BEFORE_AGENT_NODE, node_async(new BeforeAgentNode(skillsService)))
            .addNode(BEFORE_MODEL_NODE, node_async(new BeforeModelNode()))
            .addNode(MODEL_NODE, planNode)
            .addNode(AFTER_MODEL_NODE, node_async(new AfterModelNode()))
            .addNode(TOOLS_NODE, toolNode)
            .addNode(AFTER_AGENT_NODE, responseNode)
            .addEdge(START, BEFORE_AGENT_NODE)
            .addEdge(BEFORE_AGENT_NODE, BEFORE_MODEL_NODE)
            .addEdge(BEFORE_MODEL_NODE, MODEL_NODE)
            .addEdge(MODEL_NODE, AFTER_MODEL_NODE)
            .addConditionalEdges(AFTER_MODEL_NODE,
                edge_async(routeFromModel),
                EdgeMappings.builder()
                    .to(BEFORE_MODEL_NODE, "model")
                    .to(TOOLS_NODE, "tools")
                    .to(AFTER_AGENT_NODE, "respond")
                    .build())
            .addConditionalEdges(TOOLS_NODE,
                edge_async(routeFromTools),
                EdgeMappings.builder()
                    .to(BEFORE_MODEL_NODE, "model")
                    .to(AFTER_AGENT_NODE, "respond")
                    .build())
            .addEdge(AFTER_AGENT_NODE, END);

        CompileConfig.Builder configBuilder = CompileConfig.builder()
            .recursionLimit(Math.max(1, deepAgentConfig.recursionLimit()))
            .graphId(deepAgentConfig.graphId())
            .interruptBeforeEdge(deepAgentConfig.interruptBeforeEdge())
            .releaseThread(deepAgentConfig.releaseThread());

        if (deepAgentConfig.checkpointSaver() != null) {
            configBuilder.checkpointSaver(deepAgentConfig.checkpointSaver());
        }
        if (!deepAgentConfig.interruptsBefore().isEmpty()) {
            configBuilder.interruptsBefore(deepAgentConfig.interruptsBefore());
        }
        if (!deepAgentConfig.interruptsAfter().isEmpty()) {
            configBuilder.interruptsAfter(deepAgentConfig.interruptsAfter());
        }

        CompileConfig config = configBuilder.build();
        return graph.compile(config);
    }

    private static final class BeforeAgentNode implements NodeAction<CopilotDeepState> {
        private final SkillsService skillsService;

        BeforeAgentNode(SkillsService skillsService) {
            this.skillsService = skillsService;
        }

        @Override
        public Map<String, Object> apply(CopilotDeepState state) {
            Map<String, Object> update = new HashMap<>();
            update.put(CopilotDeepState.JUMP_TO, "");
            update.put(CopilotDeepState.RETURN_DIRECT, Boolean.FALSE);

            if (skillsService != null) {
                try {
                    var loadResult = skillsService.refresh();
                    var skills = skillsService.listSkills();
                    String skillsPrompt = CopilotPrompts.renderSkillsPrompt(
                        loadResult.getSourcePaths(), skills);
                    update.put(CopilotDeepState.SKILLS_PROMPT, skillsPrompt);
                    Msg.debug(this, "BeforeAgentNode loaded " + skills.size() + " skills");
                } catch (Exception e) {
                    Msg.warn(this, "Failed to load skills: " + e.getMessage());
                    update.put(CopilotDeepState.SKILLS_PROMPT,
                        CopilotPrompts.SKILLS_STATUS_PROMPT);
                }
            } else {
                update.put(CopilotDeepState.SKILLS_PROMPT,
                    CopilotPrompts.SKILLS_STATUS_PROMPT);
            }
            return update;
        }
    }

    private static final class BeforeModelNode implements NodeAction<CopilotDeepState> {
        @Override
        public Map<String, Object> apply(CopilotDeepState state) {
            Map<String, Object> update = new HashMap<>();
            update.put(CopilotDeepState.JUMP_TO, "");
            update.put(CopilotDeepState.RETURN_DIRECT, Boolean.FALSE);

            return update;
        }
    }

    private static final class AfterModelNode implements NodeAction<CopilotDeepState> {
        @Override
        public Map<String, Object> apply(CopilotDeepState state) {
            Msg.debug(this, "Copilot dispatcher: lastMessage=" + state.lastMessage().map(Object::getClass).orElse(null));
            boolean hasToolCalls = state.lastMessage()
                .filter(dev.langchain4j.data.message.AiMessage.class::isInstance)
                .map(dev.langchain4j.data.message.AiMessage.class::cast)
                .map(aiMessage -> aiMessage.toolExecutionRequests() != null && !aiMessage.toolExecutionRequests().isEmpty())
                .orElse(false);

            String nextActiveTodo = null;
            if (hasToolCalls) {
                var todos = state.todos();
                if (!todos.isEmpty()) {
                    String currentActive = state.activeTodo().orElse(null);
                    if (currentActive != null && todos.contains(currentActive)) {
                        nextActiveTodo = currentActive;
                    } else {
                        nextActiveTodo = todos.get(0);
                    }
                }
            }
            if (nextActiveTodo == null) {
                nextActiveTodo = "";
            }
            return Map.of(
                CopilotDeepState.ACTIVE_TODO, nextActiveTodo,
                CopilotDeepState.JUMP_TO, "",
                CopilotDeepState.RETURN_DIRECT, Boolean.FALSE
            );
        }
    }
}
