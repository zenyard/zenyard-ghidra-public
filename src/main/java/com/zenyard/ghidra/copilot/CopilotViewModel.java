package com.zenyard.ghidra.copilot;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import javax.swing.SwingUtilities;

/**
 * View-model layer for Copilot UI, separating business logic from UI.
 * 
 * Manages messages, loading/error states for the Copilot chat interface.
 * 
 * NOTE: This provides better separation of concerns between UI and business logic.
 */
public class CopilotViewModel {
    private static final int MAX_MESSAGE_TEXT_CHARS = 256_000;
    private static final int MAX_THINKING_TEXT_CHARS = 128_000;
    private static final int MAX_SUBAGENT_STREAM_CHARS = 128_000;
    
    /**
     * Represents a message in the chat.
     */
    public static class Message {
        private final String text;
        private final boolean fromUser;
        private final long timestamp;
        
        public Message(String text, boolean fromUser) {
            this.text = truncateTail(text, MAX_MESSAGE_TEXT_CHARS);
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

    /**
     * Represents an autocomplete suggestion.
     */
    public static class AutocompleteItem {
        private final String name;
        private final String address;

        public AutocompleteItem(String name, String address) {
            this.name = name;
            this.address = address;
        }

        public String getName() {
            return name;
        }

        public String getAddress() {
            return address;
        }
    }
    
    private final List<Message> messages;
    private final List<Runnable> listeners;
    private final List<Consumer<String>> streamChunkListeners;
    private final AtomicBoolean listenerNotifyScheduled;
    private boolean isLoading;
    private String error;
    private boolean thinking;
    private String thinkingText;
    private List<AutocompleteItem> autocompleteItems;
    private String autocompleteRequestId;
    private List<String> todos;
    private String activeTodo;
    private String currentToolName;
    private List<String> toolHistory;
    private Set<String> completedTodos;
    private Set<String> failedTodos;
    private boolean todoMinimized;
    private Map<String, String> todoStatuses;
    private boolean streamDeltaEnabled;
    private String subAgentType;
    private String subAgentStreamText;
    
    public CopilotViewModel() {
        this.messages = new CopyOnWriteArrayList<>();
        this.listeners = new CopyOnWriteArrayList<>();
        this.streamChunkListeners = new CopyOnWriteArrayList<>();
        this.listenerNotifyScheduled = new AtomicBoolean(false);
        this.isLoading = false;
        this.error = null;
        this.thinking = false;
        this.thinkingText = null;
        this.autocompleteItems = new ArrayList<>();
        this.autocompleteRequestId = null;
        this.todos = new ArrayList<>();
        this.activeTodo = null;
        this.currentToolName = null;
        this.toolHistory = new ArrayList<>();
        this.completedTodos = new LinkedHashSet<>();
        this.failedTodos = new LinkedHashSet<>();
        this.todoMinimized = false;
        this.todoStatuses = new LinkedHashMap<>();
        this.streamDeltaEnabled = false;
        this.subAgentType = null;
        this.subAgentStreamText = null;
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
        if (!listenerNotifyScheduled.compareAndSet(false, true)) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            listenerNotifyScheduled.set(false);
            for (Runnable listener : listeners) {
                listener.run();
            }
        });
    }

    public void addStreamChunkListener(Consumer<String> listener) {
        if (listener != null) {
            streamChunkListeners.add(listener);
        }
    }

    public void removeStreamChunkListener(Consumer<String> listener) {
        streamChunkListeners.remove(listener);
    }

    public void setStreamDeltaEnabled(boolean enabled) {
        this.streamDeltaEnabled = enabled;
    }

    public boolean isStreamDeltaEnabled() {
        return streamDeltaEnabled;
    }

    private void notifyStreamChunkListeners(String chunk) {
        if (!streamDeltaEnabled || chunk == null || chunk.isEmpty()) {
            return;
        }
        Runnable dispatch = () -> {
            for (Consumer<String> listener : streamChunkListeners) {
                try {
                    listener.accept(chunk);
                } catch (Exception ignore) {
                    // Stream chunks are best-effort and should never break state updates.
                }
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            dispatch.run();
        } else {
            SwingUtilities.invokeLater(dispatch);
        }
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
        this.thinkingText = truncateTail(thinkingText, MAX_THINKING_TEXT_CHARS);
        notifyListeners();
    }

    /**
     * Append a token to the current thinking text (for streaming planning tokens).
     */
    public void appendThinkingText(String token) {
        if (token == null || token.isEmpty()) {
            return;
        }
        this.thinking = true;
        this.thinkingText = appendWithTailLimit(this.thinkingText, token, MAX_THINKING_TEXT_CHARS);
        notifyListeners();
    }

    /**
     * Clear thinking text and exit thinking state.
     */
    public void clearThinkingText() {
        this.thinking = false;
        this.thinkingText = null;
        notifyListeners();
    }
    
    /**
     * Append text to the last message (for streaming).
     */
    public void appendToLastMessage(String text) {
        String chunk = text != null ? text : "";
        if (messages.isEmpty()) {
            // Create new message if none exists
            addMessage(chunk, false);
        } else {
            Message lastMessage = messages.get(messages.size() - 1);
            if (!lastMessage.isFromUser()) {
                // Append to last AI message
                String nextText = appendWithTailLimit(lastMessage.getText(), chunk, MAX_MESSAGE_TEXT_CHARS);
                Message updatedMessage = new Message(nextText, false);
                messages.set(messages.size() - 1, updatedMessage);
                notifyListeners();
            } else {
                // Create new AI message
                addMessage(chunk, false);
            }
        }
        notifyStreamChunkListeners(chunk);
    }

    /**
     * Set autocomplete results for the current query.
     */
    public void setAutocomplete(List<AutocompleteItem> items, String requestId) {
        this.autocompleteItems = items != null ? new ArrayList<>(items) : new ArrayList<>();
        this.autocompleteRequestId = requestId;
        notifyListeners();
    }

    public List<AutocompleteItem> getAutocompleteItems() {
        return new ArrayList<>(autocompleteItems);
    }

    public String getAutocompleteRequestId() {
        return autocompleteRequestId;
    }

    public void setTodos(List<String> todos) {
        List<String> sanitized = sanitizeTodos(todos);
        Set<String> nextSet = new HashSet<>(sanitized);
        boolean completedChanged = false;

        for (String todo : sanitized) {
            if (completedTodos.remove(todo)) {
                completedChanged = true;
            }
        }
        for (String existing : this.todos) {
            if (!nextSet.contains(existing) && completedTodos.add(existing)) {
                completedChanged = true;
            }
        }

        List<String> ordered = new ArrayList<>(sanitized);
        for (String existing : this.todos) {
            if (!nextSet.contains(existing)) {
                ordered.add(existing);
            }
        }

        if (Objects.equals(this.todos, ordered) && !completedChanged) {
            return;
        }
        this.todos = ordered;
        recomputeTodoStatuses();
        notifyListeners();
    }

    public List<String> getTodos() {
        return new ArrayList<>(todos);
    }

    public void clearTodos() {
        if (todos.isEmpty() && completedTodos.isEmpty() && activeTodo == null) {
            return;
        }
        todos.clear();
        completedTodos.clear();
        activeTodo = null;
        todoStatuses.clear();
        notifyListeners();
    }

    public List<String> getCompletedTodos() {
        List<String> completed = new ArrayList<>();
        for (String todo : todos) {
            if (completedTodos.contains(todo)) {
                completed.add(todo);
            }
        }
        return completed;
    }

    public List<String> getFailedTodos() {
        List<String> failed = new ArrayList<>();
        for (String todo : todos) {
            if (failedTodos.contains(todo)) {
                failed.add(todo);
            }
        }
        return failed;
    }

    public void clearCompletedTodos() {
        if (completedTodos.isEmpty()) {
            return;
        }
        completedTodos.clear();
        recomputeTodoStatuses();
        notifyListeners();
    }

    public void clearFailedTodos() {
        if (failedTodos.isEmpty()) {
            return;
        }
        failedTodos.clear();
        recomputeTodoStatuses();
        notifyListeners();
    }

    public void setActiveTodo(String activeTodo) {
        if (Objects.equals(this.activeTodo, activeTodo)) {
            return;
        }
        this.activeTodo = activeTodo;
        recomputeTodoStatuses();
        notifyListeners();
    }

    public String getActiveTodo() {
        return activeTodo;
    }

    public void setCurrentToolName(String currentToolName) {
        if (Objects.equals(this.currentToolName, currentToolName)) {
            return;
        }
        this.currentToolName = currentToolName;
        notifyListeners();
    }

    public String getCurrentToolName() {
        return currentToolName;
    }

    public void addToolHistory(String toolName) {
        if (toolName == null || toolName.isBlank()) {
            return;
        }
        toolHistory.add(toolName);
        if (toolHistory.size() > 20) {
            toolHistory = new ArrayList<>(toolHistory.subList(toolHistory.size() - 20, toolHistory.size()));
        }
        notifyListeners();
    }

    public void clearToolHistory() {
        if (toolHistory.isEmpty()) {
            return;
        }
        toolHistory.clear();
        notifyListeners();
    }

    public void setToolHistory(List<String> toolHistory) {
        List<String> next = sanitizeTodos(toolHistory);
        if (next.size() > 20) {
            next = new ArrayList<>(next.subList(next.size() - 20, next.size()));
        }
        if (Objects.equals(this.toolHistory, next)) {
            return;
        }
        this.toolHistory = next;
        notifyListeners();
    }

    public List<String> getToolHistory() {
        return new ArrayList<>(toolHistory);
    }

    public void setTodoMinimized(boolean minimized) {
        if (this.todoMinimized == minimized) {
            return;
        }
        this.todoMinimized = minimized;
        notifyListeners();
    }

    public boolean isTodoMinimized() {
        return todoMinimized;
    }

    public void finalizeTodos(String currentToolName) {
        if (todos.isEmpty() && completedTodos.isEmpty() && activeTodo == null) {
            return;
        }
        List<String> remaining = new ArrayList<>();
        boolean changed = false;
        for (String todo : todos) {
            if (isToolTodo(todo, currentToolName)) {
                changed = true;
                continue;
            }
            remaining.add(todo);
        }
        if (!completedTodos.containsAll(remaining)) {
            completedTodos.addAll(remaining);
            changed = true;
        }
        if (!failedTodos.isEmpty()) {
            failedTodos.clear();
            changed = true;
        }
        if (!Objects.equals(todos, remaining)) {
            todos = remaining;
            changed = true;
        }
        if (activeTodo != null) {
            activeTodo = null;
            changed = true;
        }
        if (changed) {
            recomputeTodoStatuses();
            notifyListeners();
        }
    }

    public void markFailedTodos(String currentToolName) {
        if (todos.isEmpty()) {
            return;
        }
        boolean changed = false;
        for (String todo : todos) {
            if (isToolTodo(todo, currentToolName)) {
                continue;
            }
            if (failedTodos.add(todo)) {
                changed = true;
            }
            if (completedTodos.remove(todo)) {
                changed = true;
            }
        }
        List<String> remaining = new ArrayList<>();
        for (String todo : todos) {
            if (isToolTodo(todo, currentToolName)) {
                changed = true;
                continue;
            }
            remaining.add(todo);
        }
        if (!Objects.equals(todos, remaining)) {
            todos = remaining;
            changed = true;
        }
        if (activeTodo != null) {
            activeTodo = null;
            changed = true;
        }
        if (changed) {
            recomputeTodoStatuses();
            notifyListeners();
        }
    }

    public Map<String, String> getTodoStatuses() {
        return new LinkedHashMap<>(todoStatuses);
    }

    public void syncTodoState(
            List<String> todos,
            String activeTodo,
            List<String> completedTodos,
            List<String> failedTodos) {
        List<String> nextTodos = sanitizeTodos(todos);
        Set<String> todoSet = new LinkedHashSet<>(nextTodos);
        Set<String> nextCompleted = new LinkedHashSet<>();
        Set<String> nextFailed = new LinkedHashSet<>();

        for (String item : sanitizeTodos(completedTodos)) {
            if (todoSet.contains(item)) {
                nextCompleted.add(item);
            }
        }
        for (String item : sanitizeTodos(failedTodos)) {
            if (todoSet.contains(item)) {
                nextFailed.add(item);
            }
        }

        String nextActiveTodo = activeTodo;
        if (nextActiveTodo != null) {
            nextActiveTodo = nextActiveTodo.trim();
            if (nextActiveTodo.isEmpty() || !todoSet.contains(nextActiveTodo)) {
                nextActiveTodo = null;
            }
        }

        if (Objects.equals(this.todos, nextTodos)
                && Objects.equals(this.activeTodo, nextActiveTodo)
                && Objects.equals(this.completedTodos, nextCompleted)
                && Objects.equals(this.failedTodos, nextFailed)) {
            return;
        }

        this.todos = nextTodos;
        this.activeTodo = nextActiveTodo;
        this.completedTodos = nextCompleted;
        this.failedTodos = nextFailed;
        recomputeTodoStatuses();
        notifyListeners();
    }

    private void recomputeTodoStatuses() {
        LinkedHashMap<String, String> next = new LinkedHashMap<>();
        for (String todo : todos) {
            String status = "pending";
            if (failedTodos.contains(todo)) {
                status = "failed";
            } else if (completedTodos.contains(todo)) {
                status = "completed";
            } else if (activeTodo != null && activeTodo.equals(todo)) {
                status = "in_progress";
            }
            next.put(todo, status);
        }
        this.todoStatuses = next;
    }

    private List<String> sanitizeTodos(List<String> input) {
        List<String> output = new ArrayList<>();
        if (input == null) {
            return output;
        }
        Set<String> seen = new HashSet<>();
        for (String item : input) {
            if (item == null) {
                continue;
            }
            String trimmed = item.trim();
            if (trimmed.isEmpty() || !seen.add(trimmed)) {
                continue;
            }
            output.add(trimmed);
        }
        return output;
    }

    private boolean isToolTodo(String todo, String currentToolName) {
        if (todo == null) {
            return false;
        }
        String trimmed = todo.trim();
        if (trimmed.isEmpty()) {
            return false;
        }
        String lower = trimmed.toLowerCase();
        if (lower.equals("current tool")) {
            return true;
        }
        if (lower.startsWith("current tool:")) {
            return true;
        }
        if (currentToolName != null && !currentToolName.isBlank()) {
            if (trimmed.equals(currentToolName)) {
                return true;
            }
            if (lower.equals(("current tool: " + currentToolName).toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    public void setSubAgentStreaming(String agentType, String text) {
        this.subAgentType = agentType;
        this.subAgentStreamText = truncateTail(text, MAX_SUBAGENT_STREAM_CHARS);
        notifyListeners();
    }

    public void appendSubAgentToken(String token) {
        if (token == null || token.isEmpty()) {
            return;
        }
        this.subAgentStreamText = appendWithTailLimit(
            this.subAgentStreamText, token, MAX_SUBAGENT_STREAM_CHARS);
        notifyListeners();
    }

    public void clearSubAgentStreaming() {
        if (this.subAgentType == null && this.subAgentStreamText == null) {
            return;
        }
        this.subAgentType = null;
        this.subAgentStreamText = null;
        notifyListeners();
    }

    public String getSubAgentType() {
        return subAgentType;
    }

    public String getSubAgentStreamText() {
        return subAgentStreamText;
    }

    private static String truncateTail(String text, int maxChars) {
        if (text == null) {
            return null;
        }
        if (maxChars <= 0 || text.length() <= maxChars) {
            return text;
        }
        return text.substring(text.length() - maxChars);
    }

    private static String appendWithTailLimit(String base, String append, int maxChars) {
        String safeBase = base != null ? base : "";
        String safeAppend = append != null ? append : "";
        if (safeAppend.isEmpty()) {
            return truncateTail(safeBase, maxChars);
        }
        if (maxChars <= 0) {
            return safeBase + safeAppend;
        }
        int keepFromBase = Math.max(0, maxChars - safeAppend.length());
        String baseTail = safeBase.length() > keepFromBase
            ? safeBase.substring(safeBase.length() - keepFromBase)
            : safeBase;
        String combined = baseTail + safeAppend;
        return truncateTail(combined, maxChars);
    }

}

