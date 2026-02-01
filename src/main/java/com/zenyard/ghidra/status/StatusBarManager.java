package com.zenyard.ghidra.status;

import java.util.Comparator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import javax.swing.SwingUtilities;

import docking.DockingWindowManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.ZenyardService;
import com.zenyard.ghidra.config.ZenyardOptions;

/**
 * Integrates with Ghidra's native StatusBar to display analysis progress, errors, and hints.
 * Uses priority-based task registration to display one active task at a time.
 * 
 * NOTE: mirrors functionality in zenyard_ida/status_bar_widget.py and zenyard_ida/ui/ui_task.py
 */
public class StatusBarManager {
    
    /**
     * Internal class to track task status information.
     */
    private static class TaskStatus {
        final String taskId;
        final int priority;
        final String status;
        final Integer progress; // null = indeterminate, 0-100 = percentage
        final boolean indeterminate;
        
        TaskStatus(String taskId, int priority, String status, Integer progress, boolean indeterminate) {
            this.taskId = taskId;
            this.priority = priority;
            this.status = status;
            this.progress = progress;
            this.indeterminate = indeterminate;
        }
    }
    
    private final PluginTool tool;
    private StatusBarComponent statusBarComponent;
    private ZenyardStatusBarProvider statusBarProvider;
    private EventDispatcher eventDispatcher;
    private StatusBarEventController eventController;
    private final StatusBarViewModel viewModel;
    private final IconRegistry iconRegistry;
    private StatusBarActions actions;
    
    // Map of active tasks by taskId
    private final Map<String, TaskStatus> activeTasks = new ConcurrentHashMap<>();
    
    public StatusBarManager(PluginTool tool) {
        this.tool = tool;
        this.statusBarComponent = null;
        this.statusBarProvider = null;
        this.eventDispatcher = null;
        this.eventController = null;
        this.viewModel = new StatusBarViewModel();
        this.iconRegistry = new IconRegistry();
        
        try {
            initializeStatusBar();
        } catch (Exception e) {
            Msg.error(this, "Failed to initialize Zenyard status bar: " + e.getMessage(), e);
        }
    }
    
    /**
     * Set the event dispatcher for status bar component to subscribe to events.
     * The dispatcher will be set on the component when it's created (asynchronously).
     */
    public void setEventDispatcher(EventDispatcher eventDispatcher) {
        this.eventDispatcher = eventDispatcher;
        if (eventDispatcher != null && eventController != null) {
            eventDispatcher.subscribe(eventController);
        }
    }

    public void setActions(StatusBarActions actions) {
        this.actions = actions;
    }
    
    /**
     * Initialize and integrate with Ghidra's native StatusBar.
     * Uses DockingWindowManager.addStatusItem() to add components to the main window's status bar.
     */
    private void initializeStatusBar() {
        SwingUtilities.invokeLater(() -> {
            try {
                // Get DockingWindowManager - try active instance first
                // DockingWindowManager windowManager = DockingWindowManager.getActiveInstance();
                DockingWindowManager windowManager = tool.getWindowManager();
                if (windowManager == null) {
                    Msg.warn(this, "tool.getWindowManager() returned null, cannot initialize status bar");
                    return;
                }
                            
                // Create status bar component
                statusBarComponent = new StatusBarComponent(tool, viewModel, actions, iconRegistry);
                statusBarProvider = new ZenyardStatusBarProvider(tool, statusBarComponent);
                
                // Wire event controller after component is created
                eventController = new StatusBarEventController(viewModel);
                if (eventDispatcher != null) {
                    eventDispatcher.subscribe(eventController);
                }
                
                // Add unified status display to status bar
                windowManager.addStatusItem(statusBarComponent.getUnifiedStatusPanel(), true, true);
                
                // Also add component provider for rerun button functionality
                tool.addComponentProvider(statusBarProvider, false); // Don't show by default, just for rerun button
                
                // Initialize display with default state
                refreshDisplay();
                            
            } catch (Exception e) {
                Msg.warn(this, "Failed to integrate with native StatusBar: " + e.getMessage());
            }
        });
    }
    
    /**
     * Register an active task with the status bar.
     * @param taskId Unique identifier for the task
     * @param priority Status bar priority (lower number = higher priority)
     */
    public void registerTask(String taskId, int priority) {
        activeTasks.put(taskId, new TaskStatus(taskId, priority, "", null, true));
        Msg.debug(this, "Registering task: " + taskId + " with priority: " + priority);
        // Immediately show the status panel when a task is registered
        SwingUtilities.invokeLater(() -> {
            if (statusBarComponent != null && statusBarComponent.getUnifiedStatusPanel() != null) {
                statusBarComponent.getUnifiedStatusPanel().setVisible(true);
            }
        });
        refreshDisplay();
    }
    
    /**
     * Unregister a task from the status bar (when finished or idle).
     * @param taskId Unique identifier for the task
     */
    public void unregisterTask(String taskId) {
        Msg.debug(this, "Unregistering task: " + taskId);
        activeTasks.remove(taskId);
        refreshDisplay();
    }
    
    /**
     * Update task status information.
     * @param taskId Unique identifier for the task
     * @param status Status message to display
     * @param progress Progress value (0-100), or null for indeterminate
     * @param indeterminate Whether to show indeterminate progress (spinner)
     */
    public void updateTaskStatus(String taskId, String status, Integer progress, boolean indeterminate) {
        TaskStatus taskStatus = activeTasks.get(taskId);
        if (taskStatus != null) {
            TaskStatus updated = new TaskStatus(
                taskId,
                taskStatus.priority,
                status != null ? status : "",
                progress,
                indeterminate
            );
            activeTasks.put(taskId, updated);
            refreshDisplay();
        }
    }
    
    /**
     * Get the highest priority active task.
     * @return Optional containing the highest priority task, or empty if none
     */
    private Optional<TaskStatus> getActiveTask() {
        return activeTasks.values().stream()
            .min(Comparator.comparingInt(ts -> ts.priority));
    }
    
    /**
     * Refresh the status bar display to show the highest priority active task.
     * When no active tasks, checks program state to show appropriate status.
     */
    private void refreshDisplay() {
        Optional<TaskStatus> activeTask = getActiveTask();
        StatusBarState state;
        StatusBarState current = viewModel.getStateSnapshot();
        if (isEulaRejected()) {
            state = StatusBarState.empty()
                .withShowReviewTerms(true)
                .withStatus("Zenyard disabled — review terms to re-enable")
                .withShowWarningIcon(current.isShowWarningIcon());
            viewModel.updateState(state);
            return;
        }
        if (activeTask.isPresent()) {
            TaskStatus task = activeTask.get();
            state = new StatusBarState(task.taskId, task.priority, task.status, task.progress,
                task.indeterminate, current.isShowRerun(), current.isShowInitialUpload(),
                current.isShowWarningIcon(), current.isShowReviewTerms());
        } else {
            boolean showInitialUpload = hasPersistedInitialQuestionsDeferred();
            if (showInitialUpload) {
                state = StatusBarState.empty()
                    .withShowInitialUpload(true)
                    .withStatus("Click to analyze with Zenyard")
                    .withShowWarningIcon(current.isShowWarningIcon())
                    .withShowReviewTerms(current.isShowReviewTerms());
            } else {
                boolean showRerun = canShowRerun() &&
                    (current.isShowRerun() || hasPersistedChangesDetected());
                if (showRerun) {
                    state = StatusBarState.empty()
                        .withShowRerun(true)
                        .withStatus("Updates detected — Click to analyze")
                        .withShowWarningIcon(current.isShowWarningIcon())
                        .withShowReviewTerms(current.isShowReviewTerms());
                } else {
                    state = StatusBarState.empty()
                        .withShowWarningIcon(current.isShowWarningIcon())
                        .withShowReviewTerms(current.isShowReviewTerms());
                }
            }
        }
        viewModel.updateState(state);
    }

    public void refreshDisplayNow() {
        refreshDisplay();
    }

    private Program getCurrentProgramSafely() {
        try {
            ZenyardService services = ZenyardService.getInstance();
            if (services == null) {
                return null;
            }
            Program program = services.getCurrentProgram();
            if (program == null || program.isClosed()) {
                return null;
            }
            return program;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean canShowRerun() {
        ZenyardService services = ZenyardService.getInstance();
        if (services == null || services.getTrackChangesTaskManager() == null) {
            return false;
        }
        return services.getTrackChangesTaskManager().shouldProcessEvents();
    }

    private boolean isEulaRejected() {
        ZenyardService services = ZenyardService.getInstance();
        if (services == null) {
            return false;
        }
        ZenyardOptions options = services.getOptions();
        if (options == null) {
            return false;
        }
        return options.getAcceptedEulaVersion() < 0;
    }

    private boolean hasPersistedChangesDetected() {
        Program program = getCurrentProgramSafely();
        if (program == null) {
            return false;
        }
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        return "true".equals(props.getString("changes_detected"));
    }

    private boolean hasPersistedInitialQuestionsDeferred() {
        Program program = getCurrentProgramSafely();
        if (program == null) {
            return false;
        }
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        String deferred = props.getString("initial_questions_deferred");
        String initialUploadComplete = props.getString("initial_upload_complete");
        return "true".equals(deferred) && !"true".equals(initialUploadComplete);
    }
    
    /**
     * Get the status bar component (for testing or advanced usage).
     */
    public StatusBarComponent getComponent() {
        return statusBarComponent;
    }
    
    public StatusBarViewModel getViewModel() {
        return viewModel;
    }

    public void dispose() {
        SwingUtilities.invokeLater(() -> {
            DockingWindowManager windowManager = tool.getWindowManager();
            if (windowManager != null && statusBarComponent != null) {
                try {
                    windowManager.removeStatusItem(statusBarComponent.getUnifiedStatusPanel());
                } catch (NullPointerException e) {
                    Msg.debug(this, "StatusBarManager: window manager disposed before status item removal");
                }
            }
            if (statusBarProvider != null) {
                tool.removeComponentProvider(statusBarProvider);
            }
        });
        if (eventDispatcher != null && eventController != null) {
            eventDispatcher.unsubscribe(eventController);
        }
    }
    
}
