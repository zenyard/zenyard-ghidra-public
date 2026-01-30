package com.zenyard.decompai.ghidra.tracking;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import com.zenyard.decompai.ghidra.events.EventDispatcher;
import com.zenyard.decompai.ghidra.storage.SyncStatusStorage;

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

    public boolean shouldProcessEvents() {
        return trackChangesTask != null && trackChangesTask.shouldProcessEvents();
    }
}
