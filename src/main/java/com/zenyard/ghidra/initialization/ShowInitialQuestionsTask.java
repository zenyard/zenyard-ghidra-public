package com.zenyard.ghidra.initialization;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import com.zenyard.ghidra.ZenyardService;
import com.zenyard.ghidra.config.ZenyardOptions;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.tasks.EventAwareTask;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;

/**
 * Background task that displays initial questions dialog.
 * Waits for READY_FOR_QUESTIONS event, shows dialog, then publishes INITIAL_DIALOG_CONFIRMED event.
 * 
 * Similar to IDA's ShowInitialQuestionsTask.
 * Runs as background task using events instead of foreground task queue.
 */
public class ShowInitialQuestionsTask extends EventAwareTask {
    
    private final PluginTool tool;
    private final Program program;
    private final ZenyardService services;
    
    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean readyForQuestions = false;
    private volatile boolean shouldStop = false;
    
    public ShowInitialQuestionsTask(PluginTool tool, Program program, ZenyardService services) {
        super("Show Initial Questions", true, false, false,
            services != null ? services.getEventDispatcher() : null);
        this.tool = tool;
        this.program = program;
        this.services = services;
    }
    
    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        Set<ZenyardEvent.EventType> types = new HashSet<>();
        types.add(ZenyardEvent.EventType.READY_FOR_QUESTIONS);
        types.add(ZenyardEvent.EventType.PROGRAM_DEACTIVATED);
        return types;
    }
    
    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.READY_FOR_QUESTIONS) {
            synchronized (waitLock) {
                readyForQuestions = true;
                waitLock.notify();
            }
        } else if (event.getType() == ZenyardEvent.EventType.PROGRAM_DEACTIVATED) {
            synchronized (waitLock) {
                shouldStop = true;
                waitLock.notify(); // Wake up any waiting threads
            }
        }
    }
    
    @Override
    protected void doRun(TaskMonitor monitor) {
        try {
            // Wait for READY_FOR_QUESTIONS event
            synchronized (waitLock) {
                while (!readyForQuestions && !monitor.isCancelled() && !shouldStop) {
                    try {
                        waitLock.wait(1000); // Wait up to 1 second, then check again
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
            
            if (monitor.isCancelled() || shouldStop) {
                return;
            }
            
            // Check if already asked
            ZenyardProgramProperties props = new ZenyardProgramProperties(program);
            String alreadyAsked = props.getString("asked_initial_questions");
            if ("true".equals(alreadyAsked)) {
                return; // Already asked
            }
            
            // Show dialog on EDT
            AtomicReference<InitialQuestionsDialog.InitialQuestionsResult> resultRef = new AtomicReference<>();
            CountDownLatch latch = new CountDownLatch(1);
            
            SwingUtilities.invokeLater(() -> {
                try {
                    ZenyardOptions options = services.getOptions();
                    InitialQuestionsDialog.InitialQuestionsResult result = 
                        InitialQuestionsDialog.showDialog(tool, options, program);
                    resultRef.set(result);
                } finally {
                    latch.countDown();
                }
            });
            
            // Wait for dialog to complete
            try {
                latch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            
            InitialQuestionsDialog.InitialQuestionsResult result = resultRef.get();
            
            if (result == null || !result.isAccepted()) {
                // User rejected or dialog was skipped
                if (services != null) {
                    com.zenyard.ghidra.status.StatusBarManager statusBarManager = services.getStatusBarManager();
                    if (statusBarManager != null) {
                        statusBarManager.refreshDisplayNow();
                    }
                }
                return;
            }
            
            // Mark as asked only if the user accepted
            props.setString("asked_initial_questions", "true");
            
            // Store preferences
            props.setString("allow_preprocessing", String.valueOf(result.isAllowPreprocessing()));
            if (result.getBinaryInstructions() != null) {
                props.setString("binary_instructions", result.getBinaryInstructions());
            }
            
            // Set ready_for_analysis
            props.setString("ready_for_analysis", "true");
            
            // Publish INITIAL_DIALOG_CONFIRMED event
            Msg.info(this, "Publishing INITIAL_DIALOG_CONFIRMED event");
            publishEvent(new ZenyardEvent(ZenyardEvent.EventType.INITIAL_DIALOG_CONFIRMED, getTaskTitle()));
            
        } catch (Exception e) {
            Msg.showError(this, tool.getActiveWindow(), "Show Initial Questions Error",
                "Failed to show initial questions: " + e.getMessage(), e);
        }
    }
}

