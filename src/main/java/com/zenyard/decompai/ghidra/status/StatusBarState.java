package com.zenyard.decompai.ghidra.status;

import java.util.Objects;

/**
 * Immutable snapshot of status bar state.
 */
public final class StatusBarState {
    private final String taskId;
    private final int priority;
    private final String status;
    private final Integer progress;
    private final boolean indeterminate;
    private final boolean showRerun;
    private final boolean showInitialUpload;

    StatusBarState(String taskId, int priority, String status, Integer progress,
            boolean indeterminate, boolean showRerun, boolean showInitialUpload) {
        this.taskId = taskId;
        this.priority = priority;
        this.status = status;
        this.progress = progress;
        this.indeterminate = indeterminate;
        this.showRerun = showRerun;
        this.showInitialUpload = showInitialUpload;
    }

    public static StatusBarState empty() {
        return new StatusBarState(null, Integer.MAX_VALUE, "Ready", null, false, false, false);
    }

    public StatusBarState withStatus(String value) {
        return new StatusBarState(taskId, priority, value, progress, indeterminate, showRerun, showInitialUpload);
    }

    public StatusBarState withProgress(Integer value, boolean isIndeterminate) {
        return new StatusBarState(taskId, priority, status, value, isIndeterminate, showRerun, showInitialUpload);
    }

    public StatusBarState withShowRerun(boolean value) {
        return new StatusBarState(taskId, priority, status, progress, indeterminate, value, showInitialUpload);
    }

    public StatusBarState withShowInitialUpload(boolean value) {
        return new StatusBarState(taskId, priority, status, progress, indeterminate, showRerun, value);
    }

    public StatusBarState withTask(String id, int taskPriority) {
        return new StatusBarState(id, taskPriority, status, progress, indeterminate, showRerun, showInitialUpload);
    }

    public String getTaskId() {
        return taskId;
    }

    public int getPriority() {
        return priority;
    }

    public String getStatus() {
        return status;
    }

    public Integer getProgress() {
        return progress;
    }

    public boolean isIndeterminate() {
        return indeterminate;
    }

    public boolean isShowRerun() {
        return showRerun;
    }

    public boolean isShowInitialUpload() {
        return showInitialUpload;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof StatusBarState)) {
            return false;
        }
        StatusBarState that = (StatusBarState) other;
        return priority == that.priority
            && indeterminate == that.indeterminate
            && showRerun == that.showRerun
            && showInitialUpload == that.showInitialUpload
            && Objects.equals(taskId, that.taskId)
            && Objects.equals(status, that.status)
            && Objects.equals(progress, that.progress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(taskId, priority, status, progress, indeterminate, showRerun, showInitialUpload);
    }
}
