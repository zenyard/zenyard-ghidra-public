package com.zenyard.decompai.ghidra.copilot.tools;

import java.util.Map;

/**
 * Listener for tool execution lifecycle events.
 */
public interface ToolExecutionListener {
    void onToolStart(String toolName, Map<String, Object> arguments);

    void onToolSuccess(String toolName, long durationMs);

    void onToolError(String toolName, Throwable error, long durationMs);
}
