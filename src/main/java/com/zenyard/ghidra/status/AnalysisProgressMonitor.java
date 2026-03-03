package com.zenyard.ghidra.status;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventConsumer;
import com.zenyard.ghidra.events.EventDispatcher;

/**
 * Monitors analysis progress, updating the status bar with applied result
 * counts instead of ETA.
 * Subscribes to ANALYSIS_STATUS_UPDATED events from PollServerStatusTask.
 *
 * NOTE: mirrors functionality in zenyard_ida/ui/status_bar_view_model.py
 */
public class AnalysisProgressMonitor implements EventConsumer {

    private static final String TASK_ID = "analyzing_in_background";
    private static final int PRIORITY = StatusBarPriorities.ANALYZING_IN_BACKGROUND;
    private static final double RESET_PROGRESS_THRESHOLD = 0.01;

    private final StatusBarManager statusBarManager;
    private final EventDispatcher eventDispatcher;
    private boolean isRegistered = false;
    private double lastProgress = -1;

    public AnalysisProgressMonitor(StatusBarManager statusBarManager, EventDispatcher eventDispatcher) {
        this.statusBarManager = statusBarManager;
        this.eventDispatcher = eventDispatcher;

        if (eventDispatcher != null) {
            eventDispatcher.subscribe(this);
        }
    }

    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        Set<ZenyardEvent.EventType> types = new HashSet<>();
        types.add(ZenyardEvent.EventType.ANALYSIS_STATUS_UPDATED);
        return types;
    }

    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() != ZenyardEvent.EventType.ANALYSIS_STATUS_UPDATED) {
            return;
        }

        Object progressObj = event.getPayloadValue("progress");

        if (progressObj == null) {
            if (isRegistered) {
                statusBarManager.unregisterTask(TASK_ID);
                isRegistered = false;
            }
            return;
        }

        if (!isRegistered) {
            statusBarManager.registerTask(TASK_ID, PRIORITY);
            isRegistered = true;
        }

        double progress = ((Number) progressObj).doubleValue();

        InferenceCountTracker tracker = statusBarManager.getInferenceCountTracker();

        if (progress <= RESET_PROGRESS_THRESHOLD && lastProgress > RESET_PROGRESS_THRESHOLD) {
            tracker.reset();
        }
        lastProgress = progress;

        Map<String, Integer> raw = tracker.snapshot();
        AppliedInferenceCounts counts = AppliedInferenceCounts.fromRawCounts(raw);
        int total = counts.getTotal();

        String statusMessage;
        if (total > 0) {
            statusMessage = "Analyzing in background - "
                + AppliedInferenceCounts.formatCompactCount(total) + " results ";
        } else {
            statusMessage = "Analyzing in background";
        }

        int progressPercent = (int) Math.round(progress * 100);
        progressPercent = Math.max(0, Math.min(100, progressPercent));

        statusBarManager.updateTaskStatus(TASK_ID, statusMessage, progressPercent, false,
            counts.formatTooltip());

        if (progress >= 1.0) {
            statusBarManager.unregisterTask(TASK_ID);
            isRegistered = false;
        }
    }

    public void dispose() {
        if (eventDispatcher != null) {
            eventDispatcher.unsubscribe(this);
        }
        if (isRegistered) {
            statusBarManager.unregisterTask(TASK_ID);
            isRegistered = false;
        }
    }
}
