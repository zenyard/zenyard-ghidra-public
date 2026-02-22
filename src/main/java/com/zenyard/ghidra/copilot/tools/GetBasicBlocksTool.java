package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

import com.zenyard.ghidra.copilot.tools.models.BasicBlock;

/**
 * Tool to get basic blocks (control flow graph) of a function.
 */
public class GetBasicBlocksTool {
    
    private final CopilotToolContext context;
    
    public GetBasicBlocksTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Return basic blocks (CFG) for one function, including start/end addresses, successors, predecessors, and approximate instruction counts.")
    public List<BasicBlock> getBasicBlocks(
            @P("Function address in the current program (hex like `0x401000`).") String address) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        return ToolUtils.executeTool(context, "get_basic_blocks", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                ghidra.program.model.listing.Function function = ToolUtils.getFunction(program, address);
                if (function == null) {
                    throw new ToolExecutionException("Failed to retrieve function from address: " + address);
                }

                // Decompile to get HighFunction with basic blocks
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(program);
                
                try {
                    TaskMonitor monitor = context.getMonitor();
                    DecompileResults results = decompiler.decompileFunction(
                        function,
                        30,
                        monitor != null ? monitor : TaskMonitor.DUMMY
                    );
                    
                    if (!results.decompileCompleted()) {
                        throw new ToolExecutionException("Failed to decompile function: " + results.getErrorMessage());
                    }
                    
                    HighFunction highFunction = results.getHighFunction();
                    if (highFunction == null) {
                        throw new ToolExecutionException("No high function available");
                    }
                    
                    List<PcodeBlockBasic> blocks = highFunction.getBasicBlocks();
                    List<BasicBlock> resultBlocks = new ArrayList<>();
                    
                    // Create a map for quick lookup
                    java.util.Map<PcodeBlockBasic, Integer> blockToIndex = new java.util.HashMap<>();
                    for (int i = 0; i < blocks.size(); i++) {
                        blockToIndex.put(blocks.get(i), i);
                    }
                    
                    for (PcodeBlockBasic block : blocks) {
                        context.checkCancelled();
                        
                        String startAddr = block.getStart() != null ? 
                            ToolUtils.formatAddress(block.getStart()) : "unknown";
                        String endAddr = block.getStop() != null ? 
                            ToolUtils.formatAddress(block.getStop()) : "unknown";
                        
                        // Get successors
                        List<String> successors = new ArrayList<>();
                        for (int i = 0; i < block.getOutSize(); i++) {
                            PcodeBlock outBlock = block.getOut(i);
                            if (outBlock instanceof PcodeBlockBasic) {
                                PcodeBlockBasic outBasic = (PcodeBlockBasic) outBlock;
                                if (outBasic.getStart() != null) {
                                    successors.add(ToolUtils.formatAddress(outBasic.getStart()));
                                }
                            }
                        }
                        
                        // Get predecessors
                        List<String> predecessors = new ArrayList<>();
                        for (int i = 0; i < block.getInSize(); i++) {
                            PcodeBlock inBlock = block.getIn(i);
                            if (inBlock instanceof PcodeBlockBasic) {
                                PcodeBlockBasic inBasic = (PcodeBlockBasic) inBlock;
                                if (inBasic.getStart() != null) {
                                    predecessors.add(ToolUtils.formatAddress(inBasic.getStart()));
                                }
                            }
                        }
                        
                        // Count instructions (approximate - use block size)
                        int instructionCount = 0;
                        if (block.getStart() != null && block.getStop() != null) {
                            // Rough estimate based on address range
                            long size = block.getStop().subtract(block.getStart());
                            instructionCount = (int) Math.max(1, size / 4); // Assume average 4 bytes per instruction
                        }
                        
                        resultBlocks.add(new BasicBlock(
                            startAddr,
                            endAddr,
                            successors,
                            predecessors,
                            instructionCount
                        ));
                    }
                    
                    return resultBlocks;
                } finally {
                    decompiler.closeProgram();
                }
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to get basic blocks: " + e.getMessage(), e);
            }
        });
    }
}
