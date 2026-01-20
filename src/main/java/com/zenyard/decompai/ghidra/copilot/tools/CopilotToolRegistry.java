package com.zenyard.decompai.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Registry for all Copilot tools.
 * Creates and manages tool instances for LangChain4j.
 */
public class CopilotToolRegistry {
    
    private final CopilotToolContext context;
    private final PluginTool tool;
    
    public CopilotToolRegistry(Program program, TaskMonitor monitor, PluginTool tool) {
        this.context = new CopilotToolContext(program, monitor, tool);
        this.tool = tool;
    }
    
    /**
     * Get all available tools for the current program.
     */
    public List<Object> getAllTools() {
        List<Object> tools = new ArrayList<>();
        
        // Core tools (always available)
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
        
        // Swift tools (conditional - only if Swift binary detected)
        Program program = context.getProgram();
        if (program != null && SwiftUtils.isSwiftBinary(program)) {
            tools.add(new GetSwiftSourceTool(context));
            tools.add(new SearchSwiftFunctionsTool(context));
        }
        
        return tools;
    }
}

