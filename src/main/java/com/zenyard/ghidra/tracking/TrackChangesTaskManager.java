package com.zenyard.ghidra.tracking;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.storage.SyncStatusStorage;
import com.zenyard.ghidra.tasks.BackgroundTaskUtil;

/**
 * Manages TrackChangesTask event listener registration.
 * 
 * Registers/unregisters the DomainObjectListener with the program
 * to track changes via events instead of polling.
 */
public class TrackChangesTaskManager {
    
    private Program currentProgram;
    private TrackChangesTask trackChangesTask;
    private final EventDispatcher eventDispatcher;
    
    public TrackChangesTaskManager(PluginTool tool, EventDispatcher eventDispatcher) {
        // Tool parameter kept for future use if needed
        this.eventDispatcher = eventDispatcher;
    }
    
    /**
     * Start tracking changes by registering the event listener and transaction listener.
     */
    public void start(Program program, SyncStatusStorage syncStatusStorage) {
        // Stop tracking previous program if any
        stop();
        
        if (program == null) {
            return;
        }
         
        currentProgram = program;
        trackChangesTask = new TrackChangesTask(program, syncStatusStorage, eventDispatcher);
        trackChangesTask.setTrackingEnabled(false);
        
        // Register domain object listener with program
        program.addListener(trackChangesTask.getListener());
        
        // Register transaction listener with program
        program.addTransactionListener(trackChangesTask.getTransactionListener());
    }
    
    /**
     * Stop tracking changes by unregistering the event listener and transaction listener.
     */
    public void stop() {
        if (currentProgram != null && trackChangesTask != null) {
            currentProgram.removeListener(trackChangesTask.getListener());
            currentProgram.removeTransactionListener(trackChangesTask.getTransactionListener());
        }
        
        currentProgram = null;
        trackChangesTask = null;
    }
    
    /**
     * Temporarily ignore events (e.g., during inference application).
     * @param ignore true to ignore events, false to resume tracking
     */
    public void setIgnoreEvents(boolean ignore) {
        if (trackChangesTask != null) {
            trackChangesTask.setIgnoreEvents(ignore);
        }
    }

    /**
     * Set whether initial analysis has completed for the current program.
     */
    public void setInitialAnalysisComplete(boolean complete) {
        if (trackChangesTask != null) {
            trackChangesTask.setInitialAnalysisComplete(complete);
        }
    }

    /**
     * Enable change tracking after program initialization completes.
     * Flushes pending events while tracking is disabled to avoid marking
     * objects dirty during initial database/application state restoration.
     *
     * Thread-safety: flushEvents() synchronously dispatches every queued
     * DomainObjectChangeEvent on the calling thread. After Ghidra's auto-analysis
     * the queue can be enormous, so we move the flush + the post-flush state
     * toggles to a background thread regardless of caller. Callers (EDT or
     * background) may invoke this without risk of freezing the UI.
     *
     * Ordering guarantee: setIgnoreEvents(true) runs synchronously on the
     * calling thread before this method returns, so any event arriving between
     * the call and the background flush is still ignored.
     */
    public void enableTrackingAfterInitialization() {
        if (currentProgram == null || trackChangesTask == null) {
            return;
        }
        final Program program = currentProgram;
        final TrackChangesTask task = trackChangesTask;
        // Suppress events synchronously — must happen before any flush so that
        // backlog events are not handed to the not-yet-fully-initialized tracker.
        task.setIgnoreEvents(true);
        BackgroundTaskUtil.execute("Zenyard: flush program events", () -> {
            if (!program.isClosed()) {
                program.flushEvents();
            }
            task.setTrackingEnabled(true);
            task.setIgnoreEvents(false);
        });
    }

    public boolean shouldProcessEvents() {
        return trackChangesTask != null && trackChangesTask.shouldProcessEvents();
    }
}
