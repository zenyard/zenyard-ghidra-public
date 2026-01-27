package com.zenyard.decompai.ghidra.util;

/**
 * Shared constants for polling, retries, and timeouts.
 */
public final class DecompaiConstants {
    private DecompaiConstants() {}

    public static final int POLL_INTERVAL_MS = 1000;
    public static final int STATUS_POLL_INTERVAL_MS = 3000;
    public static final int MAX_BACKOFF_MS = 30000;
    public static final int INITIAL_BACKOFF_MS = 1000;
    public static final int DECOMPILER_TIMEOUT_SECONDS = 30;
}
