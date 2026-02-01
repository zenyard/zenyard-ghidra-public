package com.zenyard.ghidra.tasks;

import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventConsumer;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.events.EventProducer;

import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Base task that handles event subscription lifecycle.
 */
public abstract class EventAwareTask extends Task implements EventConsumer, EventProducer {
    private final EventDispatcher eventDispatcher;

    protected EventAwareTask(String title, boolean canCancel, boolean hasProgress, boolean isModal,
            EventDispatcher eventDispatcher) {
        super(title, canCancel, hasProgress, isModal);
        this.eventDispatcher = eventDispatcher;
    }

    @Override
    public final void run(TaskMonitor monitor) {
        if (eventDispatcher != null) {
            eventDispatcher.subscribe(this);
        }
        try {
            doRun(monitor);
        } finally {
            if (eventDispatcher != null) {
                eventDispatcher.unsubscribe(this);
            }
        }
    }

    protected abstract void doRun(TaskMonitor monitor);

    @Override
    public void publishEvent(ZenyardEvent event) {
        if (eventDispatcher != null) {
            eventDispatcher.publish(event);
        }
    }

    protected EventDispatcher getEventDispatcher() {
        return eventDispatcher;
    }
}
