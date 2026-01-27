package com.zenyard.decompai.ghidra.copilot;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

/**
 * View-model layer for Copilot UI, separating business logic from UI.
 * 
 * Manages messages, loading/error states for the Copilot chat interface.
 * 
 * NOTE: This provides better separation of concerns between UI and business logic.
 */
public class CopilotViewModel {
    
    /**
     * Represents a message in the chat.
     */
    public static class Message {
        private final String text;
        private final boolean fromUser;
        private final long timestamp;
        
        public Message(String text, boolean fromUser) {
            this.text = text;
            this.fromUser = fromUser;
            this.timestamp = System.currentTimeMillis();
        }
        
        public String getText() {
            return text;
        }
        
        public boolean isFromUser() {
            return fromUser;
        }
        
        public long getTimestamp() {
            return timestamp;
        }
    }
    
    private final List<Message> messages;
    private final List<Runnable> listeners;
    private boolean isLoading;
    private String error;
    private boolean thinking;
    private String thinkingText;
    
    public CopilotViewModel() {
        this.messages = new CopyOnWriteArrayList<>();
        this.listeners = new CopyOnWriteArrayList<>();
        this.isLoading = false;
        this.error = null;
        this.thinking = false;
        this.thinkingText = null;
    }
    
    /**
     * Add a listener for view-model changes.
     */
    public void addListener(Runnable listener) {
        listeners.add(listener);
    }
    
    /**
     * Remove a listener.
     */
    public void removeListener(Runnable listener) {
        listeners.remove(listener);
    }
    
    /**
     * Notify all listeners of changes (on EDT).
     */
    private void notifyListeners() {
        SwingUtilities.invokeLater(() -> {
            for (Runnable listener : listeners) {
                listener.run();
            }
        });
    }
    
    /**
     * Add a message.
     */
    public void addMessage(Message message) {
        messages.add(message);
        notifyListeners();
    }
    
    /**
     * Add a message with text.
     */
    public void addMessage(String text, boolean fromUser) {
        addMessage(new Message(text, fromUser));
    }
    
    /**
     * Get all messages.
     */
    public List<Message> getMessages() {
        return new ArrayList<>(messages);
    }
    
    /**
     * Clear all messages.
     */
    public void clearMessages() {
        messages.clear();
        notifyListeners();
    }
    
    /**
     * Set loading state.
     */
    public void setLoading(boolean loading) {
        this.isLoading = loading;
        notifyListeners();
    }
    
    /**
     * Check if loading.
     */
    public boolean isLoading() {
        return isLoading;
    }

    /**
     * Check if the agent is currently thinking or running a tool.
     */
    public boolean isThinking() {
        return thinking;
    }

    /**
     * Get the current thinking text.
     */
    public String getThinkingText() {
        return thinkingText;
    }
    
    /**
     * Set error message.
     */
    public void setError(String error) {
        this.error = error;
        notifyListeners();
    }
    
    /**
     * Get error message.
     */
    public String getError() {
        return error;
    }
    
    /**
     * Clear error.
     */
    public void clearError() {
        this.error = null;
        notifyListeners();
    }

    /**
     * Set thinking state and optional text.
     */
    public void setThinking(boolean thinking, String thinkingText) {
        this.thinking = thinking;
        this.thinkingText = thinkingText;
        notifyListeners();
    }
    
    /**
     * Append text to the last message (for streaming).
     */
    public void appendToLastMessage(String text) {
        if (messages.isEmpty()) {
            // Create new message if none exists
            addMessage(text, false);
        } else {
            Message lastMessage = messages.get(messages.size() - 1);
            if (!lastMessage.isFromUser()) {
                // Append to last AI message
                Message updatedMessage = new Message(lastMessage.getText() + text, false);
                messages.set(messages.size() - 1, updatedMessage);
                notifyListeners();
            } else {
                // Create new AI message
                addMessage(text, false);
            }
        }
    }
}

