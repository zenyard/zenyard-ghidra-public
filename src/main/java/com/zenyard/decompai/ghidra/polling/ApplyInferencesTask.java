package com.zenyard.decompai.ghidra.polling;

import java.util.ArrayList;
import java.util.List;

import java.util.HashSet;
import java.util.Set;

import com.zenyard.decompai.ghidra.api.generated.model.Inference;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.events.EventConsumer;
import com.zenyard.decompai.ghidra.events.EventDispatcher;
import com.zenyard.decompai.ghidra.illum.InferenceApplier;
import com.zenyard.decompai.ghidra.illum.FunctionOverviewAnnotator;
import com.zenyard.decompai.ghidra.storage.InferenceStorage;
import com.zenyard.decompai.ghidra.status.StatusBarManager;
import com.zenyard.decompai.ghidra.status.StatusBarPriorities;
import com.zenyard.decompai.ghidra.tracking.TrackChangesTaskManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Background task that continuously applies inferences from the inference queue.
 * Runs in the background waiting for NEW_INFERENCES_AVAILABLE events.
 * When notified via events, applies available inferences and returns to waiting state.
 * Shows progress in the status bar.
 * 
 * NOTE: mirrors decompai_ida/trigger_apply_inferences_task.py and apply_inferences_task.py
 */
public class ApplyInferencesTask extends Task implements EventConsumer {
    
    private static final int BATCH_SIZE = 50; // Apply inferences in batches
    private static final String TASK_ID = "apply_inferences";
    private static final String LATEST_RESULTS_TASK_ID = "latest_results_applied";
    private static final int STATUS_BAR_PRIORITY = StatusBarPriorities.APPLY_INFERENCES;
    private static final int LATEST_RESULTS_PRIORITY = StatusBarPriorities.LATEST_RESULTS_APPLIED;
    
    private final DownloadInferencesTask.InferenceQueue inferenceQueue;
    private final TrackChangesTaskManager trackChangesTaskManager;
    private final StatusBarManager statusBarManager;
    private final Program program;
    private final EventDispatcher eventDispatcher;
    
    // Synchronization for waiting/notifying
    private final Object waitLock = new Object();
    private volatile boolean shouldStop = false;
    private volatile boolean newInferencesAvailable = false;
    
    public ApplyInferencesTask(PluginTool tool, 
                              DownloadInferencesTask.InferenceQueue inferenceQueue,
                              TrackChangesTaskManager trackChangesTaskManager,
                              StatusBarManager statusBarManager,
                              Program program,
                              EventDispatcher eventDispatcher) {
        super("Apply Inferences", true, true, false); // canCancel=true, hasProgress=true, isModal=false
        // Note: tool parameter kept for API compatibility but not stored
        this.inferenceQueue = inferenceQueue;
        this.trackChangesTaskManager = trackChangesTaskManager;
        this.statusBarManager = statusBarManager;
        this.program = program;
        this.eventDispatcher = eventDispatcher;
        
        // Note: TrackChangesTask event listener is already active and doesn't need to be restarted
        // The listener is registered when the program is activated and remains active
    }
    
    @Override
    public Set<DecompaiEvent.EventType> getSubscribedEventTypes() {
        Set<DecompaiEvent.EventType> types = new HashSet<>();
        types.add(DecompaiEvent.EventType.NEW_INFERENCES_AVAILABLE);
        types.add(DecompaiEvent.EventType.PROGRAM_DEACTIVATED);
        return types;
    }
    
    @Override
    public void handleEvent(DecompaiEvent event) {
        if (event.getType() == DecompaiEvent.EventType.NEW_INFERENCES_AVAILABLE) {
            Msg.info(this, "ApplyInferencesTask: Received NEW_INFERENCES_AVAILABLE event");
            synchronized (waitLock) {
                newInferencesAvailable = true;
                waitLock.notify();
                Msg.info(this, "ApplyInferencesTask: Notified waiting thread, queue size: " + inferenceQueue.size());
            }
        } else if (event.getType() == DecompaiEvent.EventType.PROGRAM_DEACTIVATED) {
            synchronized (waitLock) {
                shouldStop = true;
                waitLock.notify(); // Wake up any waiting threads
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
            Msg.info(this, "ApplyInferencesTask: Starting, waiting for new inferences");
            FunctionOverviewAnnotator overviewAnnotator = new FunctionOverviewAnnotator();
            InferenceStorage inferenceStorage = new InferenceStorage(program);
            InferenceApplier inferenceApplier = new InferenceApplier(overviewAnnotator, inferenceStorage);
            
            // Main loop: wait for notifications and apply inferences
            while (!shouldStop && !monitor.isCancelled()) {
            // Wait for new inferences to be available
            synchronized (waitLock) {
                while (!newInferencesAvailable && !shouldStop && !monitor.isCancelled()) {
                    try {
                        waitLock.wait(1000); // Wait up to 1 second, then check again
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
                
                // Reset flag after checking
                if (newInferencesAvailable) {
                    Msg.info(this, "ApplyInferencesTask: Woke up, checking queue (size: " + inferenceQueue.size() + ")");
                }
                newInferencesAvailable = false;
            }
            
            // Check if we should stop
            if (shouldStop || monitor.isCancelled()) {
                break;
            }
            
            // Check if program is still valid
            if (program == null || program.isClosed()) {
                break;
            }
            
            // Apply available inferences
            if (!inferenceQueue.isEmpty()) {
                Msg.info(this, "ApplyInferencesTask: Starting to apply " + inferenceQueue.size() + " inferences");
                applyInferencesBatch(monitor, inferenceApplier);
            } else {
                Msg.info(this, "ApplyInferencesTask: Queue is empty, continuing to wait");
            }
        }
        
        } finally {
            // Unsubscribe from events
            if (eventDispatcher != null) {
                eventDispatcher.unsubscribe(this);
            }
            
            // Cleanup: unregister status bar
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(TASK_ID);
            }
        }
    }
    
    /**
     * Apply a batch of inferences from the queue.
     */
    private void applyInferencesBatch(TaskMonitor monitor, InferenceApplier inferenceApplier) {
        // Temporarily disable change tracking to avoid marking objects as dirty
        // when we're applying our own inferences (which trigger rename events, etc.)
        if (trackChangesTaskManager != null) {
            trackChangesTaskManager.setIgnoreEvents(true);
        }
        
        int totalApplied = 0;
        
        try {                        
            // Count total inferences to apply for progress tracking
            int totalToApply = inferenceQueue.size();
            if (totalToApply == 0) {
                return;
            }
            
            // Register with status bar when starting to apply
            if (statusBarManager != null) {
                statusBarManager.registerTask(TASK_ID, STATUS_BAR_PRIORITY);
            }
                        
            // Apply all available inferences in batches
            while (!inferenceQueue.isEmpty() && !shouldStop) {
                // Collect a batch of inferences from the queue
                List<Inference> batch = new ArrayList<>();
                for (int i = 0; i < BATCH_SIZE && !inferenceQueue.isEmpty(); i++) {
                    Inference inference = inferenceQueue.dequeue();
                    if (inference != null) {
                        batch.add(inference);
                    }
                }
                
                if (!batch.isEmpty()) {
                    try {
                        inferenceApplier.applyInferences(program, batch);    
                        totalApplied += batch.size();            
                        // Update status bar with progress
                        if (statusBarManager != null) {
                            int progressPercent = calculateProgressPercent(totalApplied, totalToApply);
                            String statusMessage = "Applying results";
                            statusBarManager.updateTaskStatus(TASK_ID, statusMessage, progressPercent, false);
                            Msg.info(this, "ApplyInferencesTask: Applied " + batch.size() + " results");
                        }
                    } catch (Exception e) {
                        // Error applying inferences - continue with next batch
                    }
                }
            }
            
            // Update status bar with final messageππ
            if (statusBarManager != null && totalApplied > 0) {
                statusBarManager.registerTask(LATEST_RESULTS_TASK_ID, LATEST_RESULTS_PRIORITY);
                statusBarManager.updateTaskStatus(LATEST_RESULTS_TASK_ID, "Latest results applied", null, false);
            }
        } finally {
            // Re-enable change tracking
            if (trackChangesTaskManager != null) {
                try {
                    Thread.sleep(1000); // Wait until all current events fired.
                    trackChangesTaskManager.setIgnoreEvents(false);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            
            // Unregister status bar when done (ensures cleanup even on error or early return)
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(TASK_ID);
            }
        }
    }
    
    
    /**
     * Stop the continuous task gracefully.
     * Called when the program is deactivated.
     */
    public void stop() {
        shouldStop = true;
        synchronized (waitLock) {
            waitLock.notify(); // Wake up the waiting thread
        }
    }
    
    /**
     * Calculates the progress percentage for applied inferences.
     * 
     * @param applied Number of inferences applied
     * @param total Total number of inferences to apply
     * @return Progress percentage (0-100)
     */
    private int calculateProgressPercent(int applied, int total) {
        if (total == 0) {
            return 100;
        }
        return (int) ((applied * 100.0) / total);
    }
}
