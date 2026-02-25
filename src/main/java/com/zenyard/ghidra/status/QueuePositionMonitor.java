package com.zenyard.ghidra.status;

import java.util.HashSet;
import java.util.Set;

import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventConsumer;
import com.zenyard.ghidra.events.EventDispatcher;

/**
 * Monitors server-side queue position and displays "In queue (N)" in the
 * status bar while the binary is waiting for admission to analyse.
 * <p>
 * Subscribes to {@link ZenyardEvent.EventType#QUEUE_POSITION_UPDATED} (from
 * {@code PollServerStatusTask}) and {@link ZenyardEvent.EventType#PROGRAM_DEACTIVATED}
 * for shutdown cleanup.
 */
public class QueuePositionMonitor implements EventConsumer {

    static final String TASK_ID = "in_queue";
    private static final int PRIORITY = StatusBarPriorities.IN_QUEUE;

    private final StatusBarManager statusBarManager;
    private final EventDispatcher eventDispatcher;
    private boolean isRegistered = false;

    public QueuePositionMonitor(StatusBarManager statusBarManager, EventDispatcher eventDispatcher) {
        this.statusBarManager = statusBarManager;
        this.eventDispatcher = eventDispatcher;

        if (eventDispatcher != null) {
            eventDispatcher.subscribe(this);
        }
    }

    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        Set<ZenyardEvent.EventType> types = new HashSet<>();
        types.add(ZenyardEvent.EventType.QUEUE_POSITION_UPDATED);
        types.add(ZenyardEvent.EventType.PROGRAM_DEACTIVATED);
        return types;
    }

    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.PROGRAM_DEACTIVATED) {
            unregisterIfNeeded();
            return;
        }

        if (event.getType() == ZenyardEvent.EventType.QUEUE_POSITION_UPDATED) {
            Object raw = event.getPayloadValue("queuePosition");
            Integer queuePosition = null;
            if (raw instanceof Number) {
                queuePosition = ((Number) raw).intValue();
            }

            if (queuePosition != null && queuePosition > 0) {
                if (!isRegistered) {
                    statusBarManager.registerTask(TASK_ID, PRIORITY);
                    isRegistered = true;
                }
                String statusMessage = "In queue (" + queuePosition + " remaining)";
                statusBarManager.updateTaskStatus(TASK_ID, statusMessage, null, true);
            } else {
                unregisterIfNeeded();
            }
        }
    }

    private void unregisterIfNeeded() {
        if (isRegistered) {
            statusBarManager.unregisterTask(TASK_ID);
            isRegistered = false;
        }
    }

    public void dispose() {
        if (eventDispatcher != null) {
            eventDispatcher.unsubscribe(this);
        }
        unregisterIfNeeded();
    }
}
