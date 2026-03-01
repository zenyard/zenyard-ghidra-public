package com.zenyard.ghidra.copilot;

import java.util.function.Supplier;

import ghidra.util.task.TaskMonitorAdapter;

/**
 * Lightweight cancellation monitor for Copilot agent runs.
 *
 * Extends {@link TaskMonitorAdapter} so it can be passed wherever a
 * {@link ghidra.util.task.TaskMonitor} is expected (e.g. tool contexts),
 * while also exposing a {@link Supplier} for non-Ghidra code that only
 * needs a boolean cancellation check (e.g. subagent loops, LLM nodes).
 *
 * Lifecycle: created once in {@code CopilotController.initializeAgent()},
 * cleared at the start of each {@code sendMessage()} call, and cancelled
 * by {@code stop()}.
 */
public class CopilotCancellationMonitor extends TaskMonitorAdapter {

    public CopilotCancellationMonitor() {
        setCancelEnabled(true);
    }

    /**
     * Returns a lightweight supplier that delegates to {@link #isCancelled()}.
     * Pass this to components that should not depend on the full TaskMonitor API.
     */
    public Supplier<Boolean> asCancelledSupplier() {
        return this::isCancelled;
    }
}
