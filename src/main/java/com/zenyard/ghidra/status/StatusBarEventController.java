package com.zenyard.ghidra.status;

import java.util.Set;

import com.zenyard.ghidra.ZenyardService;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventConsumer;

/**
 * Updates the status bar state based on events.
 */
public class StatusBarEventController implements EventConsumer {
    private final StatusBarViewModel viewModel;

    public StatusBarEventController(StatusBarViewModel viewModel) {
        this.viewModel = viewModel;
    }

    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        return Set.of(
            ZenyardEvent.EventType.CHANGES_DETECTED,
            ZenyardEvent.EventType.SERVER_CONNECTIVITY_CHANGED
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
        ZenyardService services = ZenyardService.getInstance();
        if (services == null || services.getTrackChangesTaskManager() == null) {
            return false;
        }
        return services.getTrackChangesTaskManager().shouldProcessEvents();
    }
}
