package com.zenyard.ghidra.copilot.tools.models;

import java.util.List;

/**
 * Represents a basic block in a function's control flow graph.
 */
public class BasicBlock {
    
    private final String startAddress;
    private final String endAddress;
    private final List<String> successors; // Addresses of successor blocks
    private final List<String> predecessors; // Addresses of predecessor blocks
    private final int instructionCount;
    
    public BasicBlock(String startAddress, String endAddress, List<String> successors, 
                     List<String> predecessors, int instructionCount) {
        this.startAddress = startAddress;
        this.endAddress = endAddress;
        this.successors = successors;
        this.predecessors = predecessors;
        this.instructionCount = instructionCount;
    }
    
    public String getStartAddress() {
        return startAddress;
    }
    
    public String getEndAddress() {
        return endAddress;
    }
    
    public List<String> getSuccessors() {
        return successors;
    }
    
    public List<String> getPredecessors() {
        return predecessors;
    }
    
    public int getInstructionCount() {
        return instructionCount;
    }
}
