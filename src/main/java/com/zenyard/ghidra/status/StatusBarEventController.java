package com.zenyard.ghidra.status;

import java.util.Set;

import com.zenyard.ghidra.ZenyardService;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventConsumer;
import com.zenyard.ghidra.upload.QueueableObjectsDetector;
import com.zenyard.ghidra.usage.UsageState;

import ghidra.program.model.listing.Program;

/**
 * Updates the status bar state based on events.
 */
public class StatusBarEventController implements EventConsumer {
    private final StatusBarViewModel viewModel;
    private final StatusBarManager statusBarManager;

    public StatusBarEventController(StatusBarViewModel viewModel, StatusBarManager statusBarManager) {
        this.viewModel = viewModel;
        this.statusBarManager = statusBarManager;
    }

    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        return Set.of(
            ZenyardEvent.EventType.CHANGES_DETECTED,
            ZenyardEvent.EventType.SERVER_CONNECTIVITY_CHANGED,
            ZenyardEvent.EventType.USAGE_UPDATED,
            ZenyardEvent.EventType.BINARY_PAUSED_UPDATED
        );
    }

    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.SERVER_CONNECTIVITY_CHANGED) {
            Boolean connected = event.getPayloadValue("connected", Boolean.class);
            if (connected == null) {
                return;
            }
            StatusBarState current = viewModel.getStateSnapshot();
            viewModel.updateState(current.withShowWarningIcon(!connected));

            statusBarManager.refreshDisplayNow();
            return;
        }

        if (event.getType() == ZenyardEvent.EventType.USAGE_UPDATED) {
            UsageState usageState = event.getPayloadValue("usageState", UsageState.class);
            if (usageState == null) {
                return;
            }
            StatusBarState current = viewModel.getStateSnapshot();
            StatusBarState next = current.withUsageDisplay(
                usageState.getDisplayTextForStatusBar(),
                usageState.getTooltip(),
                usageState.isVisible(),
                usageState.getDisplayLevel()
            );
            viewModel.updateState(next);
            return;
        }

        if (event.getType() == ZenyardEvent.EventType.BINARY_PAUSED_UPDATED) {
            statusBarManager.refreshDisplayNow();
            return;
        }

        if (event.getType() == ZenyardEvent.EventType.CHANGES_DETECTED) {
            if (!canShowRerun()) {
                return;
            }
            StatusBarState current = viewModel.getStateSnapshot();
            StatusBarState next = current
                .withShowRerun(true)
                .withStatus("Updates detected — Click to analyze");
            viewModel.updateState(next);
        }
    }

    private boolean canShowRerun() {
        ZenyardService svc = statusBarManager.getService();
        if (svc == null || svc.getTrackChangesTaskManager() == null) {
            return false;
        }
        if (!svc.getTrackChangesTaskManager().shouldProcessEvents()) {
            return false;
        }

        Program program = svc.getCurrentProgram();
        return QueueableObjectsDetector.hasQueueableObjects(program);
    }
}
