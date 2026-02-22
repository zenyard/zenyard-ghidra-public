package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

/**
 * Tool to list defined data (global data structures).
 */
public class ListDefinedDataTool {
    
    private final CopilotToolContext context;
    
    public ListDefinedDataTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a list of defined data (global data structures) in the program.")
    public ToolOutput listDefinedData() {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        return ToolUtils.executeTool(context, "list_defined_data", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Listing listing = program.getListing();
                DataIterator dataIt = listing.getDefinedData(true);
                
                List<String> allData = new ArrayList<>();
                
                while (dataIt.hasNext()) {
                    context.checkCancelled();
                    
                    Data data = dataIt.next();
                    if (data == null) {
                        continue;
                    }
                    
                    Address addr = data.getAddress();
                    
                    String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valueRepr = "";
                    try {
                        valueRepr = data.getDefaultValueRepresentation();
                    } catch (Exception e) {
                        valueRepr = "(unreadable)";
                    }
                    
                    String dataStr = String.format("%s: %s = %s",
                        ToolUtils.formatAddress(addr),
                        label,
                        valueRepr);
                    allData.add(dataStr);
                }
                
                StringBuilder output = new StringBuilder();
                for (String entry : allData) {
                    output.append(entry).append("\n");
                }
                return ToolUtils.persistLargeOutput(context, "defined-data", output.toString(), allData.size());
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list defined data: " + e.getMessage(), e);
            }
        });
    }
}
