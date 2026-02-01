package com.zenyard.ghidra.events;

/**
 * Interface for components that produce/publish events.
 * Tasks and other components implement this to publish events to the event system.
 */
public interface EventProducer {
    /**
     * Publishes an event to the event dispatcher.
     * 
     * @param event The event to publish
     */
    void publishEvent(ZenyardEvent event);
}
