package com.zenyard.decompai.ghidra.status;

import java.util.Collections;
import java.util.Set;

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
        StatusBarState current = viewModel.getStateSnapshot();
        StatusBarState next = current
            .withShowRerun(true)
            .withStatus("Updates detected — Click to analyze");
        viewModel.updateState(next);
    }
}
