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
import com.zenyard.decompai.ghidra.events.EventProducer;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;

/**
 * Background task that checks if initial questions should be shown.
 * Waits for ANALYSIS_COMPLETE event, then publishes READY_FOR_QUESTIONS event.
 * 
 * Similar to IDA's AskInitialQuestions task.
 * Uses event-driven architecture to wait for analysis completion.
 */
public class AskInitialQuestionsTask extends Task implements EventConsumer, EventProducer {
    
    private final PluginTool tool;
    private final Program program;
    private final DecompaiServices services;
    private final EventDispatcher eventDispatcher;
    
    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean analysisComplete = false;
    private volatile boolean shouldStop = false;
    
    public AskInitialQuestionsTask(PluginTool tool, Program program, 
                                   DecompaiServices services) {
        super("Ask Initial Questions", true, false, false); // canCancel=true, hasProgress=false, isModal=false
        this.tool = tool;
        this.program = program;
        this.services = services;
        this.eventDispatcher = services != null ? services.getEventDispatcher() : null;
    }
    
    @Override
    public Set<DecompaiEvent.EventType> getSubscribedEventTypes() {
        Set<DecompaiEvent.EventType> types = new HashSet<>();
        types.add(DecompaiEvent.EventType.ANALYSIS_COMPLETE);
        types.add(DecompaiEvent.EventType.PROGRAM_DEACTIVATED);
        return types;
    }
    
    @Override
    public void handleEvent(DecompaiEvent event) {
        if (event.getType() == DecompaiEvent.EventType.ANALYSIS_COMPLETE) {
            synchronized (waitLock) {
                analysisComplete = true;
                waitLock.notify();
            }
        } else if (event.getType() == DecompaiEvent.EventType.PROGRAM_DEACTIVATED) {
            synchronized (waitLock) {
                shouldStop = true;
                waitLock.notify(); // Wake up any waiting threads
            }
        }
    }
    
    @Override
    public void publishEvent(DecompaiEvent event) {
        if (eventDispatcher != null) {
            eventDispatcher.publish(event);
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
            
            // Check initial state
            String alreadyAsked = props.getString("asked_initial_questions");
            String alreadyUploaded = props.getString("initial_upload_complete");
            
            if ("true".equals(alreadyAsked) || "true".equals(alreadyUploaded)) {
                // Already asked or uploaded - set ready_for_analysis and return
                props.setString("ready_for_analysis", "true");
                return;
            }
            
            // Check if analysis is already complete
            String alreadyCompleted = props.getString("initial_analysis_complete");
            if (!"true".equals(alreadyCompleted)) {
            // Wait for ANALYSIS_COMPLETE event
            synchronized (waitLock) {
                while (!analysisComplete && !monitor.isCancelled() && !shouldStop) {
                        try {
                            waitLock.wait(1000); // Wait up to 1 second, then check property again
                            // Re-check property in case it was set directly
                            alreadyCompleted = props.getString("initial_analysis_complete");
                            if ("true".equals(alreadyCompleted)) {
                                analysisComplete = true;
                                break;
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }
                }
            }
            
            // Check again after waiting (in case we were cancelled or analysis never completed)
            if (monitor.isCancelled() || shouldStop) {
                return;
            }
            
            // Check if still need to ask (might have been set while waiting)
            alreadyAsked = props.getString("asked_initial_questions");
            alreadyUploaded = props.getString("initial_upload_complete");
            
            if ("true".equals(alreadyAsked) || "true".equals(alreadyUploaded)) {
                props.setString("ready_for_analysis", "true");
                return;
            }
            
            // Publish READY_FOR_QUESTIONS event to trigger ShowInitialQuestionsTask
            Msg.info(this, "Publishing READY_FOR_QUESTIONS event");
            publishEvent(new DecompaiEvent(DecompaiEvent.EventType.READY_FOR_QUESTIONS, getTaskTitle()));
            
        } catch (Exception e) {
            Msg.showError(this, tool.getActiveWindow(), "Ask Initial Questions Error",
                "Failed to check initial questions: " + e.getMessage(), e);
        } finally {
            // Unsubscribe from events
            if (eventDispatcher != null) {
                eventDispatcher.unsubscribe(this);
            }
        }
    }
    
}

