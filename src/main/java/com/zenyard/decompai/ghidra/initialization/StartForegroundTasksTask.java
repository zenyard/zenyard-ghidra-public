package com.zenyard.decompai.ghidra.initialization;

import java.util.HashSet;
import java.util.Set;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import com.zenyard.decompai.ghidra.DecompaiServices;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.events.EventConsumer;
import com.zenyard.decompai.ghidra.events.EventDispatcher;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;
import com.zenyard.decompai.ghidra.tasks.ForegroundTask;

/**
 * Background task that continuously monitors the foreground task queue and processes
 * foreground tasks one at a time.
 * 
 * Similar to IDA's StartForegroundTasksTask.
 * Uses event/callback to wait for queue updates instead of polling.
 */
public class StartForegroundTasksTask extends Task implements EventConsumer {
    
    private final PluginTool tool;
    private final Program program;
    private final DecompaiServices services;
    private final EventDispatcher eventDispatcher;
    private volatile boolean shouldStop = false;
    
    public StartForegroundTasksTask(PluginTool tool, Program program, DecompaiServices services) {
        super("Start Foreground Tasks", true, false, false); // canCancel=true, hasProgress=false, isModal=false
        this.tool = tool;
        this.program = program;
        this.services = services;
        this.eventDispatcher = services != null ? services.getEventDispatcher() : null;
    }
    
    @Override
    public Set<DecompaiEvent.EventType> getSubscribedEventTypes() {
        Set<DecompaiEvent.EventType> types = new HashSet<>();
        types.add(DecompaiEvent.EventType.PROGRAM_DEACTIVATED);
        return types;
    }
    
    @Override
    public void handleEvent(DecompaiEvent event) {
        if (event.getType() == DecompaiEvent.EventType.PROGRAM_DEACTIVATED) {
            shouldStop = true;
            // Notify waiting thread if any
            synchronized (services) {
                services.notifyAll();
            }
        }
    }
    
    @Override
    public void run(TaskMonitor monitor) {
        // Subscribe to events
        if (eventDispatcher != null) {
            eventDispatcher.subscribe(this);
        }
        
        try {
            DecompaiProgramProperties props = new DecompaiProgramProperties(program);
            
            // Wait for initial analysis to complete before processing foreground tasks
            waitForAnalysisComplete(props, monitor);
            
            if (monitor.isCancelled() || shouldStop) {
                return;
            }
            
            // Process foreground tasks one at a time
            while (!monitor.isCancelled() && !shouldStop) {
                // Wait for queue to become non-empty (uses event notification, not polling)
                try {
                    services.waitForForegroundTask();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                
                if (monitor.isCancelled() || shouldStop) {
                    break;
                }
                
                // Process all queued tasks one at a time
                while (!monitor.isCancelled() && !shouldStop && !services.isForegroundTaskQueueEmpty()) {
                    ForegroundTask foregroundTask = services.pollForegroundTask();
                    if (foregroundTask != null) {
                        try {
                            services.setForegroundTaskActive(true);
                            // Execute the foreground task
                            foregroundTask.run(program);
                        } catch (Exception e) {
                            Msg.showError(this, tool.getActiveWindow(), "Foreground Task Error",
                                "Failed to execute foreground task: " + e.getMessage(), e);
                        } finally {
                            services.setForegroundTaskActive(false);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.showError(this, tool.getActiveWindow(), "Start Foreground Tasks Error",
                "Failed to process foreground tasks: " + e.getMessage(), e);
        } finally {
            // Unsubscribe from events
            if (eventDispatcher != null) {
                eventDispatcher.unsubscribe(this);
            }
        }
    }
    
    /**
     * Wait for initial analysis to complete using event notification (no polling).
     * Blocks on services lock until notified by the event handler in DecompaiGhidraPlugin.
     */
    private void waitForAnalysisComplete(DecompaiProgramProperties props, TaskMonitor monitor) {
        // Check if already complete
        String alreadyCompleted = props.getString("initial_analysis_complete");
        if ("true".equals(alreadyCompleted)) {
            return;
        }
        
        // Wait for analysis completion using event notification (no polling loop)
        // The event handler in DecompaiGhidraPlugin will call services.notifyAll() when analysis completes
        while (!monitor.isCancelled() && !shouldStop) {
            // Check property when notified (event-driven, not polling)
            alreadyCompleted = props.getString("initial_analysis_complete");
            if ("true".equals(alreadyCompleted)) {
                return;
            }
            
            // Wait for state change notification (blocks until notified)
            synchronized (services) {
                try {
                    services.wait(); // Wait indefinitely until notified
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }
}

