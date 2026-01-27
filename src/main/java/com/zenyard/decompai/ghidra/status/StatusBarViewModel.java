package com.zenyard.decompai.ghidra.status;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Thread-safe status bar view model with listener support.
 */
public class StatusBarViewModel {
    private final AtomicReference<StatusBarState> state;
    private final List<Consumer<StatusBarState>> listeners;

    public StatusBarViewModel() {
        this.state = new AtomicReference<>(StatusBarState.empty());
        this.listeners = new CopyOnWriteArrayList<>();
    }

    public StatusBarState getStateSnapshot() {
        return state.get();
    }

    public void updateState(StatusBarState nextState) {
        if (nextState == null) {
            return;
        }
        state.set(nextState);
        for (Consumer<StatusBarState> listener : listeners) {
            listener.accept(nextState);
        }
    }

    public void addListener(Consumer<StatusBarState> listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(Consumer<StatusBarState> listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }
}
