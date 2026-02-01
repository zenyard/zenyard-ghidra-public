package com.zenyard.ghidra.status;

import java.util.HashSet;
import java.util.Set;

import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventConsumer;
import com.zenyard.ghidra.events.EventDispatcher;

/**
 * Monitors analysis progress and ETA, updating the status bar accordingly.
 * Subscribes to ANALYSIS_STATUS_UPDATED events from PollServerStatusTask.
 * 
 * NOTE: mirrors functionality in zenyard_ida/ui/status_bar_view_model.py
 */
public class AnalysisProgressMonitor implements EventConsumer {
    
    private static final String TASK_ID = "analyzing_in_background";
    private static final int PRIORITY = StatusBarPriorities.ANALYZING_IN_BACKGROUND;
    
    private final StatusBarManager statusBarManager;
    private final EventDispatcher eventDispatcher;
    private boolean isRegistered = false;
    
    public AnalysisProgressMonitor(StatusBarManager statusBarManager, EventDispatcher eventDispatcher) {
        this.statusBarManager = statusBarManager;
        this.eventDispatcher = eventDispatcher;
        
        // Don't register task here - wait for first ANALYSIS_STATUS_UPDATED event
        // This ensures the status bar component is initialized first
        
        // Subscribe to events
        if (eventDispatcher != null) {
            eventDispatcher.subscribe(this);
        }
    }
    
    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        Set<ZenyardEvent.EventType> types = new HashSet<>();
        types.add(ZenyardEvent.EventType.ANALYSIS_STATUS_UPDATED);
        return types;
    }
    
    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.ANALYSIS_STATUS_UPDATED) {
            // Extract progress and ETA from payload
            Object progressObj = event.getPayloadValue("progress");
            Object etaObj = event.getPayloadValue("eta");
            
            ghidra.util.Msg.debug(this, "AnalysisProgressMonitor: Received ANALYSIS_STATUS_UPDATED event, progress=" 
                + progressObj + ", eta=" + etaObj);
            
            if (progressObj == null) {
                // No progress data - unregister if registered
                ghidra.util.Msg.debug(this, "AnalysisProgressMonitor: No progress data, unregistering task");
                if (isRegistered) {
                    statusBarManager.unregisterTask(TASK_ID);
                    isRegistered = false;
                }
                return;
            }
            
            // Ensure task is registered
            if (!isRegistered) {
                ghidra.util.Msg.debug(this, "AnalysisProgressMonitor: Registering task with priority " + PRIORITY);
                statusBarManager.registerTask(TASK_ID, PRIORITY);
                isRegistered = true;
            }
            
            double progress = ((Number) progressObj).doubleValue();
            Double eta = null;
            if (etaObj != null) {
                eta = ((Number) etaObj).doubleValue();
            }
            
            // Format ETA label
            String etaLabel;
            if (eta != null) {
                String formattedEta = formatEta(eta);
                etaLabel = formattedEta + " left";
            } else {
                etaLabel = "calculating ETA...";
            }
            
            // Build status message
            String statusMessage = "Analyzing in background - " + etaLabel;
            
            // Convert progress (0.0-1.0) to percentage (0-100)
            int progressPercent = (int) Math.round(progress * 100);
            
            // Clamp progress to valid range
            if (progressPercent < 0) {
                progressPercent = 0;
            } else if (progressPercent > 100) {
                progressPercent = 100;
            }
            
            // Update status bar
            statusBarManager.updateTaskStatus(TASK_ID, statusMessage, progressPercent, false);
            
            // If progress is complete, unregister task
            if (progress >= 1.0) {
                statusBarManager.unregisterTask(TASK_ID);
                isRegistered = false;
            }
        }
    }
    
    /**
     * Format ETA in seconds to human-readable string.
     * Mirrors _format_eta() in zenyard_ida/ui/status_bar_view_model.py
     * 
     * @param seconds ETA in seconds
     * @return Formatted string like "2h 30m" or "45m"
     */
    private String formatEta(double seconds) {
        // Convert t minutes (round up)
        long minutes = (long) Math.ceil(seconds / 60.0);
        
        // Calculate hours and remaining minutes
        long hours = minutes / 60;
        long minutesLeft = minutes % 60;
        
        if (hours > 0) {
            if (minutesLeft == 0) {
                return hours + "h";
            } else {
                return hours + "h " + minutesLeft + "m";
            }
        } else {
            return minutesLeft + "m";
        }
    }
    
    /**
     * Cleanup: unsubscribe from events and unregister task.
     */
    public void dispose() {
        if (eventDispatcher != null) {
            eventDispatcher.unsubscribe(this);
        }
        if (isRegistered) {
            statusBarManager.unregisterTask(TASK_ID);
            isRegistered = false;
        }
    }
}
