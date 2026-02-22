package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.Memory;

import com.zenyard.ghidra.copilot.tools.models.Segment;
import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

/**
 * Tool to list memory segments/blocks.
 */
public class ListSegmentsTool {
    
    private final CopilotToolContext context;
    
    public ListSegmentsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a list of memory segments (blocks) in the program.")
    public ToolOutput listSegments() {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        return ToolUtils.executeTool(context, "list_segments", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Memory memory = program.getMemory();
                MemoryBlock[] blocks = memory.getBlocks();
                
                List<Segment> allSegments = new ArrayList<>();
                
                for (MemoryBlock block : blocks) {
                    context.checkCancelled();
                    
                    String blockName = block.getName();
                    
                    String permissions = "";
                    if (block.isRead()) permissions += "r";
                    if (block.isWrite()) permissions += "w";
                    if (block.isExecute()) permissions += "x";
                    
                    long length = block.getEnd().subtract(block.getStart()) + 1;
                    
                    allSegments.add(new Segment(
                        blockName,
                        ToolUtils.formatAddress(block.getStart()),
                        ToolUtils.formatAddress(block.getEnd()),
                        permissions,
                        length
                    ));
                }
                
                StringBuilder output = new StringBuilder();
                for (Segment segment : allSegments) {
                    output.append(segment.getName())
                        .append(" ")
                        .append(segment.getStartAddress())
                        .append(" ")
                        .append(segment.getEndAddress())
                        .append(" ")
                        .append(segment.getPermissions())
                        .append("\n");
                }
                return ToolUtils.persistLargeOutput(context, "segments", output.toString(), allSegments.size());
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list segments: " + e.getMessage(), e);
            }
        });
    }
}
