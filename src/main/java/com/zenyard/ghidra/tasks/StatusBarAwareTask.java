package com.zenyard.ghidra.tasks;

import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.status.StatusBarManager;

import ghidra.util.task.TaskMonitor;

/**
 * Base task that wraps status bar registration lifecycle.
 */
public abstract class StatusBarAwareTask extends EventAwareTask {
    @FunctionalInterface
    protected interface StatusBarTaskAction {
        void run() throws Exception;
    }

    private final StatusBarManager statusBarManager;
    private final String taskId;
    private final int priority;

    protected StatusBarAwareTask(String title, boolean canCancel, boolean hasProgress, boolean isModal,
            EventDispatcher eventDispatcher, StatusBarManager statusBarManager, String taskId, int priority) {
        super(title, canCancel, hasProgress, isModal, eventDispatcher);
        this.statusBarManager = statusBarManager;
        this.taskId = taskId;
        this.priority = priority;
    }

    protected final void runWithStatusBar(StatusBarTaskAction action) throws Exception {
        if (statusBarManager != null) {
            statusBarManager.registerTask(taskId, priority);
        }
        try {
            action.run();
        } finally {
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(taskId);
            }
        }
    }

    protected final StatusBarManager getStatusBarManager() {
        return statusBarManager;
    }

    protected final String getStatusBarTaskId() {
        return taskId;
    }

    @Override
    protected abstract void doRun(TaskMonitor monitor);
}
