package com.zenyard.ghidra.events;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import ghidra.util.Msg;

/**
 * Central event dispatcher for Zenyard task communication.
 * Thread-safe event distribution using a simple subscription model.
 * 
 * Events are distributed synchronously in the publishing thread for simplicity.
 */
public class EventDispatcher {
    
    // Map from event type to list of consumers subscribed to that type
    private final ConcurrentHashMap<ZenyardEvent.EventType, List<EventConsumer>> subscriptions;
    
    // Track all consumers for unsubscribe operations
    private final ConcurrentHashMap<EventConsumer, Set<ZenyardEvent.EventType>> consumerSubscriptions;
    
    public EventDispatcher() {
        this.subscriptions = new ConcurrentHashMap<>();
        this.consumerSubscriptions = new ConcurrentHashMap<>();
    }
    
    /**
     * Subscribes a consumer to receive events of the types it declares interest in.
     * 
     * @param consumer The consumer to subscribe
     */
    public void subscribe(EventConsumer consumer) {
        if (consumer == null) {
            return;
        }
        
        Set<ZenyardEvent.EventType> eventTypes = consumer.getSubscribedEventTypes();
        if (eventTypes == null || eventTypes.isEmpty()) {
            Msg.warn(this, "Consumer " + consumer.getClass().getSimpleName() + " subscribes to no event types");
            return;
        }
        
        // Store consumer's subscriptions for efficient unsubscribe
        consumerSubscriptions.put(consumer, eventTypes);
        
        // Add consumer to each event type's subscription list
        for (ZenyardEvent.EventType eventType : eventTypes) {
            subscriptions.computeIfAbsent(eventType, k -> new CopyOnWriteArrayList<>()).add(consumer);
            Msg.debug(this, "Subscribed " + consumer.getClass().getSimpleName() + " to " + eventType);
        }
    }
    
    /**
     * Unsubscribes a consumer from all event types.
     * 
     * @param consumer The consumer to unsubscribe
     */
    public void unsubscribe(EventConsumer consumer) {
        if (consumer == null) {
            return;
        }
        
        Set<ZenyardEvent.EventType> eventTypes = consumerSubscriptions.remove(consumer);
        if (eventTypes == null) {
            return; // Not subscribed
        }
        
        // Remove consumer from each event type's subscription list
        for (ZenyardEvent.EventType eventType : eventTypes) {
            List<EventConsumer> consumers = subscriptions.get(eventType);
            if (consumers != null) {
                consumers.remove(consumer);
                if (consumers.isEmpty()) {
                    subscriptions.remove(eventType);
                }
                Msg.debug(this, "Unsubscribed " + consumer.getClass().getSimpleName() + " from " + eventType);
            }
        }
    }
    
    /**
     * Publishes an event to all subscribed consumers.
     * Events are distributed synchronously in the calling thread.
     * 
     * @param event The event to publish
     */
    public void publish(ZenyardEvent event) {
        if (event == null) {
            return;
        }
        
        List<EventConsumer> consumers = subscriptions.get(event.getType());
        if (consumers == null || consumers.isEmpty()) {
            Msg.debug(this, "No consumers subscribed to " + event.getType() + " from " + event.getSource());
            return;
        }
        
        Msg.info(this, "Publishing " + event.getType() + " from " + event.getSource() + " to " + consumers.size() + " consumer(s)");
        
        // Distribute event to all subscribers synchronously
        for (EventConsumer consumer : consumers) {
            try {
                if (consumer.shouldHandle(event)) {
                    consumer.handleEvent(event);
                }
            } catch (Exception e) {
                Msg.error(this, "Error handling event " + event.getType() + " in consumer " 
                    + consumer.getClass().getSimpleName(), e);
            }
        }
    }
    
    /**
     * Gets the number of consumers subscribed to a specific event type.
     * 
     * @param eventType The event type
     * @return Number of subscribers
     */
    public int getSubscriberCount(ZenyardEvent.EventType eventType) {
        List<EventConsumer> consumers = subscriptions.get(eventType);
        return consumers != null ? consumers.size() : 0;
    }
    
    /**
     * Gets all event types that have subscribers.
     * 
     * @return Set of event types with at least one subscriber
     */
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        return Collections.unmodifiableSet(subscriptions.keySet());
    }
}
