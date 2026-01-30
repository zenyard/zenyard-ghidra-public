package com.zenyard.decompai.ghidra.status;

import java.util.Collections;
import java.util.Set;

import com.zenyard.decompai.ghidra.ZenyardService;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.events.EventConsumer;

/**
 * Updates the status bar state based on events.
 */
public class StatusBarEventController implements EventConsumer {
    private final StatusBarViewModel viewModel;

    public StatusBarEventController(StatusBarViewModel viewModel) {
        this.viewModel = viewModel;
    }

    @Override
    public Set<DecompaiEvent.EventType> getSubscribedEventTypes() {
        return Collections.singleton(DecompaiEvent.EventType.CHANGES_DETECTED);
    }

    @Override
    public void handleEvent(DecompaiEvent event) {
        if (event.getType() != DecompaiEvent.EventType.CHANGES_DETECTED) {
            return;
        }
        if (!canShowRerun()) {
            return;
        }
        StatusBarState current = viewModel.getStateSnapshot();
        StatusBarState next = current
            .withShowRerun(true)
            .withStatus("Updates detected — Click to analyze");
        viewModel.updateState(next);
    }

    private boolean canShowRerun() {
        ZenyardService services = ZenyardService.getInstance();
        if (services == null || services.getTrackChangesTaskManager() == null) {
            return false;
        }
        return services.getTrackChangesTaskManager().shouldProcessEvents();
    }
}
