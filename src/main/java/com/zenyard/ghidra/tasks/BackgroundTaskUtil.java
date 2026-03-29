package com.zenyard.ghidra.tasks;

import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Utility for creating and executing background tasks without a progress dialog.
 */
public final class BackgroundTaskUtil {

    private BackgroundTaskUtil() {
    }

    /**
     * Creates a background Task wrapping the given Runnable.
     */
    public static Task background(String title, Runnable work) {
        return new Task(title, false, false, false) { // canCancel=false, hasProgress=false, isModal=false
            @Override
            public void run(TaskMonitor monitor) {
                work.run();
            }
        };
    }

    /**
     * Executes a pre-built Task on a daemon background thread.
     */
    public static void execute(Task task) {
        TaskMonitor monitor = TaskMonitor.DUMMY;
        String threadName = "Background Task - " + task.getTaskTitle();
        Thread taskThread = new Thread(() -> {
            Thread.currentThread().setName(threadName);
            try {
                task.monitoredRun(monitor);
            } catch (Exception e) {
                Msg.error(BackgroundTaskUtil.class,
                    "Error executing background task: " + task.getTaskTitle(), e);
            }
        });
        taskThread.setDaemon(true);
        taskThread.start();
    }

    /**
     * Convenience: creates and executes a background task in one call.
     */
    public static void execute(String title, Runnable work) {
        execute(background(title, work));
    }
}
