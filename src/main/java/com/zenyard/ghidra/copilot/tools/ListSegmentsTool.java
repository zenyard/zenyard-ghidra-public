package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.Memory;

import com.zenyard.ghidra.copilot.tools.models.PagedResults;
import com.zenyard.ghidra.copilot.tools.models.Segment;

/**
 * Tool to list memory segments/blocks.
 */
public class ListSegmentsTool {
    
    private final CopilotToolContext context;
    
    public ListSegmentsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a paginated list of memory segments (blocks) in the program. " +
          "If next_cursor is not empty, there are more pages which can be fetched using the cursor parameter.")
    public PagedResults<Segment> listSegments(String cursor) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        if (cursor != null) {
            args.put("cursor", cursor);
        }
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
                
                // Parse cursor (use block name as cursor)
                String cursorName = cursor;
                boolean pastCursor = (cursorName == null);
                
                for (MemoryBlock block : blocks) {
                    context.checkCancelled();
                    
                    String blockName = block.getName();
                    
                    // Skip until past cursor
                    if (!pastCursor) {
                        if (blockName.compareTo(cursorName) > 0) {
                            pastCursor = true;
                        } else {
                            continue;
                        }
                    }
                    
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
                
                // Paginate
                int pageSize = 200;
                List<Segment> pageSegments;
                String nextCursor = null;
                
                if (allSegments.size() > pageSize) {
                    pageSegments = allSegments.subList(0, pageSize);
                    nextCursor = pageSegments.get(pageSize - 1).getName();
                } else {
                    pageSegments = allSegments;
                }
                
                return new PagedResults<>(pageSegments, nextCursor);
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list segments: " + e.getMessage(), e);
            }
        });
    }
}
