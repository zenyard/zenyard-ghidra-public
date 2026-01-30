package com.zenyard.decompai.ghidra.initialization;

import java.util.HashSet;
import java.util.Set;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import com.zenyard.decompai.ghidra.ZenyardService;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.tasks.EventAwareTask;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;

/**
 * Background task that checks if initial questions should be shown.
 * Waits for ANALYSIS_COMPLETE event, then publishes READY_FOR_QUESTIONS event.
 * 
 * Similar to IDA's AskInitialQuestions task.
 * Uses event-driven architecture to wait for analysis completion.
 */
public class AskInitialQuestionsTask extends EventAwareTask {
    
    private final PluginTool tool;
    private final Program program;
    
    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean analysisComplete = false;
    private volatile boolean shouldStop = false;
    
    public AskInitialQuestionsTask(PluginTool tool, Program program, 
                                   ZenyardService services) {
        super("Ask Initial Questions", true, false, false,
            services != null ? services.getEventDispatcher() : null);
        this.tool = tool;
        this.program = program;
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
    protected void doRun(TaskMonitor monitor) {
        try {
            DecompaiProgramProperties props = new DecompaiProgramProperties(program);
            
            // Check initial state
            String alreadyAsked = props.getString("asked_initial_questions");
            String alreadyUploaded = props.getString("initial_upload_complete");
            String deferred = props.getString("initial_questions_deferred");
            if ("true".equals(deferred) && !"true".equals(alreadyUploaded)) {
                // User deferred; status bar button will be shown instead of auto dialog.
                return;
            }
            
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
            deferred = props.getString("initial_questions_deferred");
            if ("true".equals(deferred) && !"true".equals(alreadyUploaded)) {
                return;
            }
            
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
        }
    }
    
}

