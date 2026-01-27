package com.zenyard.decompai.ghidra.events;

import java.util.Set;

/**
 * Interface for components that consume/handle events.
 * Tasks implement this to subscribe to and handle events from the event system.
 */
public interface EventConsumer {
    /**
     * Handles an event that this consumer is subscribed to.
     * This method is called by the EventDispatcher when an event of a subscribed type is published.
     * 
     * @param event The event to handle
     */
    void handleEvent(DecompaiEvent event);
    
    /**
     * Returns the set of event types this consumer is interested in.
     * The EventDispatcher uses this to determine which events to deliver to this consumer.
     * 
     * @return Set of event types this consumer subscribes to
     */
    Set<DecompaiEvent.EventType> getSubscribedEventTypes();

    /**
     * Optional filter for events this consumer should handle.
     * Default is true to preserve existing behavior.
     */
    default boolean shouldHandle(DecompaiEvent event) {
        return true;
    }
}
