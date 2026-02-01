package com.zenyard.ghidra.copilot;

import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Simple rate limiter for Copilot API calls.
 * Limits to 15 requests per 60 seconds (matches IDA implementation).
 * 
 * Uses a semaphore-based sliding window approach.
 */
public class CopilotRateLimiter {
    
    private static final int MAX_REQUESTS = 15;
    private static final long TIME_WINDOW_SECONDS = 60;
    
    private final Semaphore semaphore;
    private final long[] requestTimes;
    private int currentIndex = 0;
    private final Object lock = new Object();
    
    public CopilotRateLimiter() {
        this.semaphore = new Semaphore(MAX_REQUESTS, true); // Fair semaphore
        this.requestTimes = new long[MAX_REQUESTS];
    }
    
    /**
     * Acquire permission to make a request.
     * Blocks until a permit is available.
     * 
     * @throws InterruptedException if interrupted while waiting
     */
    public void acquire() throws InterruptedException {
        synchronized (lock) {
            // Clean up old requests outside the time window
            long currentTime = System.currentTimeMillis();
            long windowStart = currentTime - (TIME_WINDOW_SECONDS * 1000);
            
            // Remove requests older than the time window
            while (currentIndex > 0 && requestTimes[(currentIndex - 1) % MAX_REQUESTS] < windowStart) {
                currentIndex--;
                semaphore.release();
            }
        }
        
        // Acquire permit (blocks if no permits available)
        semaphore.acquire();
        
        // Record request time
        synchronized (lock) {
            requestTimes[currentIndex % MAX_REQUESTS] = System.currentTimeMillis();
            currentIndex++;
        }
    }
    
    /**
     * Try to acquire permission without blocking.
     * 
     * @return true if permit was acquired, false otherwise
     */
    public boolean tryAcquire() {
        synchronized (lock) {
            // Clean up old requests
            long currentTime = System.currentTimeMillis();
            long windowStart = currentTime - (TIME_WINDOW_SECONDS * 1000);
            
            while (currentIndex > 0 && requestTimes[(currentIndex - 1) % MAX_REQUESTS] < windowStart) {
                currentIndex--;
                semaphore.release();
            }
        }
        
        // Try to acquire permit
        if (semaphore.tryAcquire()) {
            synchronized (lock) {
                requestTimes[currentIndex % MAX_REQUESTS] = System.currentTimeMillis();
                currentIndex++;
            }
            return true;
        }
        
        return false;
    }
    
    /**
     * Try to acquire permission with timeout.
     * 
     * @param timeout the maximum time to wait
     * @param unit the time unit
     * @return true if permit was acquired, false if timeout
     * @throws InterruptedException if interrupted while waiting
     */
    public boolean tryAcquire(long timeout, TimeUnit unit) throws InterruptedException {
        synchronized (lock) {
            // Clean up old requests
            long currentTime = System.currentTimeMillis();
            long windowStart = currentTime - (TIME_WINDOW_SECONDS * 1000);
            
            while (currentIndex > 0 && requestTimes[(currentIndex - 1) % MAX_REQUESTS] < windowStart) {
                currentIndex--;
                semaphore.release();
            }
        }
        
        // Try to acquire permit with timeout
        if (semaphore.tryAcquire(timeout, unit)) {
            synchronized (lock) {
                requestTimes[currentIndex % MAX_REQUESTS] = System.currentTimeMillis();
                currentIndex++;
            }
            return true;
        }
        
        return false;
    }
}

