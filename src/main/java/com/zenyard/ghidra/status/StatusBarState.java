package com.zenyard.ghidra.status;

import java.util.Objects;

import com.zenyard.ghidra.usage.UsageLevel;

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
    private final boolean showWarningIcon;
    private final boolean showReviewTerms;
    private final String usageText;
    private final String usageTooltip;
    private final boolean usageVisible;
    private final UsageLevel usageLevel;

    StatusBarState(String taskId, int priority, String status, Integer progress,
            boolean indeterminate, boolean showRerun, boolean showInitialUpload,
            boolean showWarningIcon, boolean showReviewTerms, String usageText,
            String usageTooltip, boolean usageVisible, UsageLevel usageLevel) {
        this.taskId = taskId;
        this.priority = priority;
        this.status = status;
        this.progress = progress;
        this.indeterminate = indeterminate;
        this.showRerun = showRerun;
        this.showInitialUpload = showInitialUpload;
        this.showWarningIcon = showWarningIcon;
        this.showReviewTerms = showReviewTerms;
        this.usageText = usageText;
        this.usageTooltip = usageTooltip;
        this.usageVisible = usageVisible;
        this.usageLevel = usageLevel;
    }

    public static StatusBarState empty() {
        return new StatusBarState(
            null,
            Integer.MAX_VALUE,
            "Ready",
            null,
            false,
            false,
            false,
            false,
            false,
            "",
            "",
            false,
            UsageLevel.NORMAL
        );
    }

    public StatusBarState withStatus(String value) {
        return new StatusBarState(taskId, priority, value, progress, indeterminate, showRerun,
            showInitialUpload, showWarningIcon, showReviewTerms, usageText, usageTooltip, usageVisible, usageLevel);
    }

    public StatusBarState withProgress(Integer value, boolean isIndeterminate) {
        return new StatusBarState(taskId, priority, status, value, isIndeterminate, showRerun,
            showInitialUpload, showWarningIcon, showReviewTerms, usageText, usageTooltip, usageVisible, usageLevel);
    }

    public StatusBarState withShowRerun(boolean value) {
        return new StatusBarState(taskId, priority, status, progress, indeterminate, value,
            showInitialUpload, showWarningIcon, showReviewTerms, usageText, usageTooltip, usageVisible, usageLevel);
    }

    public StatusBarState withShowInitialUpload(boolean value) {
        return new StatusBarState(taskId, priority, status, progress, indeterminate, showRerun, value,
            showWarningIcon, showReviewTerms, usageText, usageTooltip, usageVisible, usageLevel);
    }

    public StatusBarState withShowWarningIcon(boolean value) {
        return new StatusBarState(taskId, priority, status, progress, indeterminate, showRerun,
            showInitialUpload, value, showReviewTerms, usageText, usageTooltip, usageVisible, usageLevel);
    }

    public StatusBarState withShowReviewTerms(boolean value) {
        return new StatusBarState(taskId, priority, status, progress, indeterminate, showRerun,
            showInitialUpload, showWarningIcon, value, usageText, usageTooltip, usageVisible, usageLevel);
    }

    public StatusBarState withTask(String id, int taskPriority) {
        return new StatusBarState(id, taskPriority, status, progress, indeterminate, showRerun,
            showInitialUpload, showWarningIcon, showReviewTerms, usageText, usageTooltip, usageVisible, usageLevel);
    }

    public StatusBarState withUsageDisplay(String text, String tooltip, boolean visible, UsageLevel level) {
        return new StatusBarState(taskId, priority, status, progress, indeterminate, showRerun,
            showInitialUpload, showWarningIcon, showReviewTerms, text, tooltip, visible, level);
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

    public boolean isShowWarningIcon() {
        return showWarningIcon;
    }

    public boolean isShowReviewTerms() {
        return showReviewTerms;
    }

    public String getUsageText() {
        return usageText;
    }

    public String getUsageTooltip() {
        return usageTooltip;
    }

    public boolean isUsageVisible() {
        return usageVisible;
    }

    public UsageLevel getUsageLevel() {
        return usageLevel;
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
            && showWarningIcon == that.showWarningIcon
            && showReviewTerms == that.showReviewTerms
            && usageVisible == that.usageVisible
            && Objects.equals(taskId, that.taskId)
            && Objects.equals(status, that.status)
            && Objects.equals(progress, that.progress)
            && Objects.equals(usageText, that.usageText)
            && Objects.equals(usageTooltip, that.usageTooltip)
            && usageLevel == that.usageLevel;
    }

    @Override
    public int hashCode() {
        return Objects.hash(taskId, priority, status, progress, indeterminate, showRerun,
            showInitialUpload, showWarningIcon, showReviewTerms, usageText, usageTooltip, usageVisible, usageLevel);
    }
}
