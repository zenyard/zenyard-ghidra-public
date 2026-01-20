package com.zenyard.decompai.ghidra.status;

/**
 * Defines status bar priority values for all background tasks.
 * 
 * Lower numbers = higher priority (displayed first when multiple tasks are active).
 * The status bar displays only one task at a time, showing the highest priority active task.
 * 
 * Priority values:
 * - 10-19: Critical upload/processing tasks (highest priority)
 * - 20-29: Binary registration and setup
 * - 30-39: Server polling and status checking
 * - 40-49: Download operations
 * - 50-59: File upload operations
 * - 60-69: Revision queueing and uploading
 * - 70-79: Background monitoring tasks (lowest priority)
 */
public class StatusBarPriorities {

    /** Waiting for Ghidra analysis (very high priority - should show above most things) */
    /** Waiting for Ghidra auto-analysis to complete */
    public static final int WAITING_FOR_GHIDRA = 10;

    // Binary registration and setup
    /** Binary registration task */
    public static final int REGISTER_BINARY = 20;

    // File upload operations
    /** Upload original files task */
    public static final int UPLOAD_ORIGINAL_FILES = 25;

    // Revision queueing and uploading
    /** Upload revisions task */
    public static final int UPLOAD_REVISIONS = 30;
    
    /** Queue revisions task */
    public static final int QUEUE_REVISIONS = 35;
    
    // Analysis progress display
    /** Analyzing in background task */
    public static final int ANALYZING_IN_BACKGROUND = 40;

    // Inference application (active processing)
    /** Apply inferences task */
    public static final int APPLY_INFERENCES = 45;

    // Download operations
    /** Download inferences task */
    public static final int DOWNLOAD_INFERENCES = 50;
    
    /** Track changes task - monitors program changes */
    public static final int TRACK_CHANGES = 55;
                
    // Completion messages (lowest priority - only shown when nothing else is active)
    /** Latest results applied - shown when all inferences are applied and queue is empty */
    public static final int LATEST_RESULTS_APPLIED = 65;
    
}

