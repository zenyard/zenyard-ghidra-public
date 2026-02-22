package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import com.zenyard.ghidra.copilot.CopilotPrompts;
import com.zenyard.ghidra.copilot.deepagent.CopilotTaskToolBuilder;
import com.zenyard.ghidra.copilot.deepagent.LangSmithTracer;
import com.zenyard.ghidra.copilot.storage.CopilotArtifactStorage;
/**
 * Registry for all Copilot tools.
 * Creates and manages tool instances for LangChain4j.
 */
public class CopilotToolRegistry {
    
    private final CopilotToolContext context;
    private final PluginTool tool;
    private final dev.langchain4j.model.chat.StreamingChatModel subAgentStreamingModel;
    private final String systemPrompt;
    private final long subAgentTimeoutMs;
    private final int subAgentRecursionLimit;
    private final LangSmithTracer tracer;
    private final CopilotTaskToolBuilder.SubAgentProgressListener progressListener;
    
    public CopilotToolRegistry(
            Program program,
            TaskMonitor monitor,
            PluginTool tool,
            ToolExecutionListener toolExecutionListener,
            CopilotArtifactStorage artifactStorage,
            dev.langchain4j.model.chat.StreamingChatModel subAgentStreamingModel,
            String systemPrompt) {
        this(program, monitor, tool, toolExecutionListener, artifactStorage,
             subAgentStreamingModel, systemPrompt, 180_000L, 25, null, null);
    }

    public CopilotToolRegistry(
            Program program,
            TaskMonitor monitor,
            PluginTool tool,
            ToolExecutionListener toolExecutionListener,
            CopilotArtifactStorage artifactStorage,
            dev.langchain4j.model.chat.StreamingChatModel subAgentStreamingModel,
            String systemPrompt,
            long subAgentTimeoutMs,
            int subAgentRecursionLimit) {
        this(program, monitor, tool, toolExecutionListener, artifactStorage,
             subAgentStreamingModel, systemPrompt, subAgentTimeoutMs, subAgentRecursionLimit, null, null);
    }

    public CopilotToolRegistry(
            Program program,
            TaskMonitor monitor,
            PluginTool tool,
            ToolExecutionListener toolExecutionListener,
            CopilotArtifactStorage artifactStorage,
            dev.langchain4j.model.chat.StreamingChatModel subAgentStreamingModel,
            String systemPrompt,
            long subAgentTimeoutMs,
            int subAgentRecursionLimit,
            LangSmithTracer tracer) {
        this(program, monitor, tool, toolExecutionListener, artifactStorage,
             subAgentStreamingModel, systemPrompt, subAgentTimeoutMs, subAgentRecursionLimit, tracer, null);
    }

    public CopilotToolRegistry(
            Program program,
            TaskMonitor monitor,
            PluginTool tool,
            ToolExecutionListener toolExecutionListener,
            CopilotArtifactStorage artifactStorage,
            dev.langchain4j.model.chat.StreamingChatModel subAgentStreamingModel,
            String systemPrompt,
            long subAgentTimeoutMs,
            int subAgentRecursionLimit,
            LangSmithTracer tracer,
            CopilotTaskToolBuilder.SubAgentProgressListener progressListener) {
        this.context = new CopilotToolContext(program, monitor, tool, toolExecutionListener, artifactStorage);
        this.tool = tool;
        this.subAgentStreamingModel = subAgentStreamingModel;
        this.systemPrompt = systemPrompt;
        this.subAgentTimeoutMs = subAgentTimeoutMs;
        this.subAgentRecursionLimit = subAgentRecursionLimit;
        this.tracer = tracer;
        this.progressListener = progressListener;
    }
    
    /**
     * Get all available tools for the current program.
     */
    public List<Object> getAllTools() {
        List<Object> tools = new ArrayList<>();
        
        // Core tools (always available)
        tools.add(new WriteTodosTool());
        tools.add(new GetCurrentFunctionTool(context, tool));
        tools.add(new GetSymbolAddressByNameTool(context));
        tools.add(new ListFunctionsTool(context));
        tools.add(new DecompileFunctionTool(context));
        tools.add(new RenameFunctionLocalVariableTool(context));
        tools.add(new RenameSymbolTool(context));
        tools.add(new ListCallingFunctionsTool(context));
        tools.add(new GetFunctionCommentTool(context));
        tools.add(new SetFunctionCommentTool(context));
        tools.add(new SetFunctionPrototypeTool(context));
        tools.add(new GetLocalTypesTool(context));
        tools.add(new SearchFunctionCommentsTool(context));
        
        // Phase 1: High-priority tools
        tools.add(new GetXrefsToTool(context));
        tools.add(new GetXrefsFromTool(context));
        tools.add(new DisassembleFunctionTool(context));
        tools.add(new ListStringsTool(context));
        tools.add(new GetAddressDetailsTool(context));
        
        // Phase 2: Medium-priority tools
        tools.add(new ListSegmentsTool(context));
        tools.add(new ListImportsTool(context));
        tools.add(new ListExportsTool(context));
        tools.add(new ListNamespacesTool(context));
        tools.add(new ListDefinedDataTool(context));
        tools.add(new ReadDataAtAddressTool(context));
        tools.add(new ListCalledFunctionsTool(context));
        
        // Phase 3: Advanced tools
        tools.add(new GetBasicBlocksTool(context));
        tools.add(new GetStackFrameTool(context));
        tools.add(new SetLocalVariableTypeTool(context));
        tools.add(new GoToAddressTool(context, tool));
        tools.add(new GetCurrentAddressTool(context, tool));
        
        // Swift tools (conditional - only if Swift binary detected)
        Program program = context.getProgram();
        if (program != null && SwiftUtils.isSwiftBinary(program)) {
            tools.add(new GetSwiftSourceTool(context));
            tools.add(new SearchSwiftFunctionsTool(context));
        }

        // Register the task tool after all domain tools are known,
        // passing domain tools so subagents get full Ghidra tool access.
        tools.add(1, buildTaskTool(tools));

        return tools;
    }

    private Object buildTaskTool(List<Object> domainTools) {
        List<CopilotTaskToolBuilder.SubAgent> subAgents = List.of(
            new CopilotTaskToolBuilder.SubAgent(
                "general-purpose",
                "General-purpose subagent for complex independent tasks.",
                systemPrompt + "\n\n" + CopilotPrompts.TASK_SYSTEM_PROMPT + "\n\n" + CopilotPrompts.subagentRolePrompt("general-purpose"),
                List.of()
            ),
            new CopilotTaskToolBuilder.SubAgent(
                "explore",
                "Exploration subagent for focused repository and binary analysis.",
                systemPrompt + "\n\n" + CopilotPrompts.TASK_SYSTEM_PROMPT + "\n\n" + CopilotPrompts.subagentRolePrompt("explore"),
                List.of()
            ),
            new CopilotTaskToolBuilder.SubAgent(
                "researcher",
                "Research subagent for deep evidence gathering and synthesis.",
                systemPrompt + "\n\n" + CopilotPrompts.TASK_SYSTEM_PROMPT + "\n\n" + CopilotPrompts.subagentRolePrompt("researcher"),
                List.of()
            ),
            new CopilotTaskToolBuilder.SubAgent(
                "critic",
                "Critic subagent for plan and output review.",
                systemPrompt + "\n\n" + CopilotPrompts.TASK_SYSTEM_PROMPT + "\n\n" + CopilotPrompts.subagentRolePrompt("critic"),
                List.of()
            ),
            new CopilotTaskToolBuilder.SubAgent(
                "toolrunner",
                "Toolrunner subagent for execution-focused planning.",
                systemPrompt + "\n\n" + CopilotPrompts.TASK_SYSTEM_PROMPT + "\n\n" + CopilotPrompts.subagentRolePrompt("toolrunner"),
                List.of()
            )
        );

        try {
            CopilotTaskToolBuilder builder = new CopilotTaskToolBuilder()
                .streamingChatModel(subAgentStreamingModel)
                .subAgents(subAgents)
                .subAgentTimeoutMs(subAgentTimeoutMs)
                .subAgentRecursionLimit(subAgentRecursionLimit)
                .tracer(tracer)
                .progressListener(progressListener);
            if (domainTools != null && !domainTools.isEmpty()) {
                builder.toolObjects(domainTools);
            }
            return builder.build();
        } catch (Exception e) {
            ghidra.util.Msg.error(this, "Failed to build streaming task tool: " + e.getMessage(), e);
            throw new RuntimeException("Failed to build task tool", e);
        }
    }
}

