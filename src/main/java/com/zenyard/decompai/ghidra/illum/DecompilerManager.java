package com.zenyard.decompai.ghidra.illum;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Helper for decompiler lifecycle management.
 */
public class DecompilerManager {
    public DecompileResults decompileFunction(Program program, Function function, int timeoutSeconds, TaskMonitor monitor) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);
        try {
            DecompileOptions options = new DecompileOptions();
            decompiler.setOptions(options);
            return decompiler.decompileFunction(function, timeoutSeconds, monitor);
        } finally {
            decompiler.closeProgram();
        }
    }
}
