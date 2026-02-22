package com.zenyard.ghidra.copilot.tools;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import com.zenyard.ghidra.copilot.storage.CopilotArtifactStorage;

/**
 * Context object passed to tools for accessing Ghidra program and monitor.
 * 
 * This provides tools with access to:
 * - Current Program instance
 * - TaskMonitor for cancellation support
 * - PluginTool for accessing services
 * - Any other shared context needed by tools
 */
public class CopilotToolContext {
    
    private final Program program;
    private final TaskMonitor monitor;
    private final PluginTool tool;
    private final ToolExecutionListener toolExecutionListener;
    private final CopilotArtifactStorage artifactStorage;
    
    public CopilotToolContext(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
        this.tool = null;
        this.toolExecutionListener = null;
        this.artifactStorage = null;
    }
    
    public CopilotToolContext(Program program, TaskMonitor monitor, PluginTool tool) {
        this.program = program;
        this.monitor = monitor;
        this.tool = tool;
        this.toolExecutionListener = null;
        this.artifactStorage = null;
    }

    public CopilotToolContext(
            Program program,
            TaskMonitor monitor,
            PluginTool tool,
            ToolExecutionListener toolExecutionListener,
            CopilotArtifactStorage artifactStorage) {
        this.program = program;
        this.monitor = monitor;
        this.tool = tool;
        this.toolExecutionListener = toolExecutionListener;
        this.artifactStorage = artifactStorage;
    }
    
    public Program getProgram() {
        return program;
    }
    
    public TaskMonitor getMonitor() {
        return monitor;
    }
    
    public PluginTool getTool() {
        return tool;
    }

    public ToolExecutionListener getToolExecutionListener() {
        return toolExecutionListener;
    }

    public CopilotArtifactStorage getArtifactStorage() {
        return artifactStorage;
    }
    
    /**
     * Check if the operation has been cancelled.
     * Throws CancelledException if cancelled.
     */
    public void checkCancelled() {
        if (monitor != null) {
            try {
                monitor.checkCanceled();
            } catch (ghidra.util.exception.CancelledException e) {
                throw new RuntimeException("Operation cancelled", e);
            }
        }
    }
}

