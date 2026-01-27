package com.zenyard.decompai.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.app.services.CodeViewerService;
import ghidra.program.util.ProgramLocation;

import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Tool to navigate to a specific address in the Ghidra UI.
 */
public class GoToAddressTool {
    
    private final CopilotToolContext context;
    private final PluginTool tool;
    
    public GoToAddressTool(CopilotToolContext context, PluginTool tool) {
        this.context = context;
        this.tool = tool;
    }
    
    @Tool("Navigates the Ghidra UI to the given address. " +
          "This will change the current location in the code viewer.")
    public String goToAddress(String address) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        return ToolUtils.executeTool(context, "go_to_address", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Address addr = ToolUtils.parseAddress(program, address);
                if (addr == null) {
                    throw new ToolExecutionException("Invalid address: " + address);
                }

                if (tool == null) {
                    throw new ToolExecutionException("Plugin tool not available");
                }

                CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
                if (codeViewer == null) {
                    throw new ToolExecutionException("Code viewer service not available");
                }

                AtomicBoolean success = new AtomicBoolean(false);
                RuntimeException[] exceptionHolder = new RuntimeException[1];
                
                SwingUtilities.invokeAndWait(() -> {
                    try {
                        ProgramLocation location = new ProgramLocation(program, addr);
                        codeViewer.goTo(location, false); // centerOnScreen = false
                        success.set(true);
                    } catch (Exception e) {
                        exceptionHolder[0] = new RuntimeException("Failed to navigate to address: " + e.getMessage(), e);
                    }
                });
                
                if (exceptionHolder[0] != null) {
                    throw exceptionHolder[0];
                }
                
                if (!success.get()) {
                    throw new ToolExecutionException("Failed to navigate to address");
                }
                
                return "Successfully navigated to address: " + address;
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to go to address: " + e.getMessage(), e);
            }
        });
    }
}
