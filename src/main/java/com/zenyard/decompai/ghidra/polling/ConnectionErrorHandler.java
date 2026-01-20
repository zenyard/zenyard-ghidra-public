package com.zenyard.decompai.ghidra.polling;

import java.net.ConnectException;
import java.net.UnknownHostException;

/**
 * Utility class for handling connection errors and exponential backoff.
 * Provides common functionality for polling tasks that need to handle
 * network connection failures gracefully.
 */
public class ConnectionErrorHandler {
    
    /**
     * Finds the root cause of an exception by unwrapping nested causes.
     * 
     * @param e The exception to analyze
     * @return The root cause exception
     */
    public static Throwable findRootCause(Throwable e) {
        Throwable rootCause = e;
        while (rootCause.getCause() != null && rootCause.getCause() != rootCause) {
            rootCause = rootCause.getCause();
        }
        return rootCause;
    }
    
    /**
     * Determines if an exception is a connection error.
     * Checks for ConnectException, UnknownHostException, or messages containing "ConnectException".
     * 
     * @param e The exception to check
     * @return true if the exception is a connection error, false otherwise
     */
    public static boolean isConnectionError(Throwable e) {
        Throwable rootCause = findRootCause(e);
        return rootCause instanceof ConnectException ||
               rootCause instanceof UnknownHostException ||
               (e.getMessage() != null && e.getMessage().contains("ConnectException"));
    }
    
    /**
     * Calculates exponential backoff delay in milliseconds.
     * Formula: initialBackoff * (2 ^ min(consecutiveFailures - 1, 5)), capped at maxBackoff.
     * This gives: 1x, 2x, 4x, 8x, 16x, 32x (max) of the initial backoff.
     * 
     * @param consecutiveFailures Number of consecutive connection failures
     * @param initialBackoff Initial backoff delay in milliseconds
     * @param maxBackoff Maximum backoff delay in milliseconds
     * @return The calculated backoff delay in milliseconds
     */
    public static int calculateBackoff(int consecutiveFailures, int initialBackoff, int maxBackoff) {
        // Exponential backoff: 2^(min(consecutiveFailures - 1, 5))
        // This limits the exponent to 5 (max 32x multiplier)
        int exponent = Math.min(consecutiveFailures - 1, 5);
        long backoff = initialBackoff * (1L << exponent);
        return (int) Math.min(backoff, maxBackoff);
    }
    
    /**
     * Handles a connection error by calculating backoff and sleeping.
     * If interrupted during sleep, calls the onInterrupt callback.
     * 
     * @param e The connection error exception
     * @param consecutiveFailures Number of consecutive connection failures (will be incremented)
     * @param initialBackoff Initial backoff delay in milliseconds
     * @param maxBackoff Maximum backoff delay in milliseconds
     * @param onInterrupt Callback to run if interrupted during backoff sleep
     * @return The updated consecutive failures count (incremented by 1)
     * @throws InterruptedException If interrupted during backoff sleep
     */
    public static int handleConnectionError(Throwable e, int consecutiveFailures,
                                           int initialBackoff, int maxBackoff,
                                           Runnable onInterrupt) throws InterruptedException {
        int updatedFailures = consecutiveFailures + 1;
        int backoffMs = calculateBackoff(updatedFailures, initialBackoff, maxBackoff);
        
        try {
            Thread.sleep(backoffMs);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            if (onInterrupt != null) {
                onInterrupt.run();
            }
            throw ie;
        }
        
        return updatedFailures;
    }
}

