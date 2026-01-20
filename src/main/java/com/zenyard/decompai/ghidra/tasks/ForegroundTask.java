package com.zenyard.decompai.ghidra.tasks;

import ghidra.program.model.listing.Program;

/**
 * Base interface for foreground tasks that execute while showing a dialog or wait box.
 * 
 * Similar to IDA's ForegroundTask pattern.
 * Foreground tasks are executed by StartForegroundTasksTask one at a time.
 */
public interface ForegroundTask {
    /**
     * Run the foreground task.
     * This method is called by StartForegroundTasksTask when the task is dequeued.
     * 
     * @param program The current program
     */
    void run(Program program);
}

