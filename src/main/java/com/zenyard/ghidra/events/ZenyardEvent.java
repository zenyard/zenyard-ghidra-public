package com.zenyard.ghidra.events;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Base event class for Zenyard task communication.
 * Events are immutable and carry type information, timestamp, source, and optional payload data.
 */
public class ZenyardEvent {
    
    /**
     * Event types used throughout the Zenyard plugin.
     */
    public enum EventType {
        /** New inferences have been downloaded and are ready to be applied */
        NEW_INFERENCES_AVAILABLE,
        
        /** Initial questions dialog has been confirmed by user */
        INITIAL_DIALOG_CONFIRMED,
        
        /** Changes to the program have been detected */
        CHANGES_DETECTED,
        
        /** Initial analysis by Ghidra has completed */
        ANALYSIS_COMPLETE,
        
        /** Binary has been registered with the server */
        BINARY_REGISTERED,
        
        /** Binary ID is now available (published after registration) */
        BINARY_ID_AVAILABLE,
        
        /** Original files upload has completed */
        UPLOAD_ORIGINAL_FILES_COMPLETE,
        
        /** Revisions have been queued and are ready for upload */
        REVISIONS_QUEUED,
        
        /** Revisions have been uploaded */
        REVISIONS_UPLOADED,
        
        /** Initial upload process has completed */
        INITIAL_UPLOAD_COMPLETE,
        
        /** System is ready to show initial questions dialog */
        READY_FOR_QUESTIONS,
        
        /** Program has been deactivated - tasks should terminate */
        PROGRAM_DEACTIVATED,
        
        /** Server revision has been updated by PollServerStatusTask */
        SERVER_REVISION_UPDATED,
        
        /** Analysis status (progress and ETA) has been updated by PollServerStatusTask */
        ANALYSIS_STATUS_UPDATED,

        /** Server connectivity changed (payload: connected = true/false) */
        SERVER_CONNECTIVITY_CHANGED
    }
    
    private final EventType type;
    private final long timestamp;
    private final String source;
    private final Map<String, Object> payload;
    
    /**
     * Creates a new ZenyardEvent with the specified type and source.
     * 
     * @param type The event type
     * @param source The source task/component that published this event
     */
    public ZenyardEvent(EventType type, String source) {
        this(type, source, null);
    }
    
    /**
     * Creates a new ZenyardEvent with the specified type, source, and payload.
     * 
     * @param type The event type
     * @param source The source task/component that published this event
     * @param payload Optional payload data (can be null)
     */
    public ZenyardEvent(EventType type, String source, Map<String, Object> payload) {
        this.type = type;
        this.source = source;
        this.timestamp = System.currentTimeMillis();
        this.payload = payload != null ? Collections.unmodifiableMap(new HashMap<>(payload)) : Collections.emptyMap();
    }

    /**
     * Create a new builder for an event type and source.
     */
    public static Builder builder(EventType type, String source) {
        return new Builder(type, source);
    }
    
    /**
     * Gets the event type.
     * 
     * @return The event type
     */
    public EventType getType() {
        return type;
    }
    
    /**
     * Gets the timestamp when the event was created.
     * 
     * @return Timestamp in milliseconds since epoch
     */
    public long getTimestamp() {
        return timestamp;
    }
    
    /**
     * Gets the source that published this event.
     * 
     * @return Source name (typically task name)
     */
    public String getSource() {
        return source;
    }
    
    /**
     * Gets the payload data.
     * 
     * @return Immutable map of payload data (never null, but may be empty)
     */
    public Map<String, Object> getPayload() {
        return payload;
    }
    
    /**
     * Gets a payload value by key.
     * 
     * @param key The payload key
     * @return The payload value, or null if not present
     */
    public Object getPayloadValue(String key) {
        return payload.get(key);
    }
    
    /**
     * Gets a payload value by key with type casting.
     * 
     * @param key The payload key
     * @param clazz The expected type
     * @return The payload value cast to the specified type, or null if not present or wrong type
     */
    @SuppressWarnings("unchecked")
    public <T> T getPayloadValue(String key, Class<T> clazz) {
        Object value = payload.get(key);
        if (value != null && clazz.isInstance(value)) {
            return (T) value;
        }
        return null;
    }
    
    @Override
    public String toString() {
        return String.format("ZenyardEvent{type=%s, source='%s', timestamp=%d, payloadSize=%d}",
            type, source, timestamp, payload.size());
    }

    /**
     * Builder for ZenyardEvent payloads.
     */
    public static class Builder {
        private final EventType type;
        private final String source;
        private final Map<String, Object> payload = new HashMap<>();

        private Builder(EventType type, String source) {
            this.type = type;
            this.source = source;
        }

        public Builder withPayload(String key, Object value) {
            if (key != null && value != null) {
                payload.put(key, value);
            }
            return this;
        }

        public ZenyardEvent build() {
            return new ZenyardEvent(type, source, payload);
        }
    }
}
