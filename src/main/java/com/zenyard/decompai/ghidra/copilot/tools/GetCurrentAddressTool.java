package com.zenyard.decompai.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.app.services.CodeViewerService;
import ghidra.program.util.ProgramLocation;

/**
 * Tool to get the current address (cursor position) in the Ghidra UI.
 */
public class GetCurrentAddressTool {
    
    private final CopilotToolContext context;
    private final PluginTool tool;
    
    public GetCurrentAddressTool(CopilotToolContext context, PluginTool tool) {
        this.context = context;
        this.tool = tool;
    }
    
    @Tool("Returns the current address (cursor position) in the Ghidra code viewer. " +
          "Returns null if no location is currently selected.")
    public String getCurrentAddress() {
        return ToolUtils.executeTool(context, "get_current_address", java.util.Collections.emptyMap(), () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                if (tool == null) {
                    throw new ToolExecutionException("Plugin tool not available");
                }

                CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
                if (codeViewer == null) {
                    throw new ToolExecutionException("Code viewer service not available");
                }

                ProgramLocation location = codeViewer.getCurrentLocation();
                if (location == null) {
                    return null;
                }

                Address addr = location.getAddress();
                return ToolUtils.formatAddress(addr);
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to get current address: " + e.getMessage(), e);
            }
        });
    }
}
