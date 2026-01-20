package com.zenyard.decompai.ghidra.status;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Comparator;
import java.util.Optional;

import javax.swing.SwingUtilities;

import docking.DockingWindowManager;
import docking.StatusBar;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import com.zenyard.decompai.ghidra.events.EventDispatcher;

/**
 * Integrates with Ghidra's native StatusBar to display analysis progress, errors, and hints.
 * Uses priority-based task registration to display one active task at a time.
 * 
 * NOTE: mirrors functionality in decompai_ida/status_bar_widget.py and decompai_ida/ui/ui_task.py
 */
public class StatusBarManager {
    
    /**
     * Internal class to track task status information.
     */
    private static class TaskStatus {
        @SuppressWarnings("unused")
        final String taskId;
        final int priority;
        String status;
        Integer progress; // null = indeterminate, 0-100 = percentage
        boolean indeterminate;
        
        TaskStatus(String taskId, int priority) {
            this.taskId = taskId;
            this.priority = priority;
            this.status = "";
            this.progress = null;
            this.indeterminate = true;
        }
    }
    
    private final PluginTool tool;
    private StatusBar statusBar;
    private DecompaiStatusBarComponent statusBarComponent;
    private DecompaiStatusBarProvider statusBarProvider;
    private EventDispatcher eventDispatcher;
    
    // Map of active tasks by taskId
    private final Map<String, TaskStatus> activeTasks = new ConcurrentHashMap<>();
    
    // Reference to services to access current program for state checking
    private com.zenyard.decompai.ghidra.DecompaiServices services;
    
    public StatusBarManager(PluginTool tool) {
        this.tool = tool;
        this.statusBar = null;
        this.statusBarComponent = null;
        this.statusBarProvider = null;
        this.eventDispatcher = null;
        this.services = null;
        
        try {
            initializeStatusBar();
        } catch (Exception e) {
            Msg.error(this, "Failed to initialize DecompAI status bar: " + e.getMessage(), e);
        }
    }
    
    /**
     * Set the event dispatcher for status bar component to subscribe to events.
     * The dispatcher will be set on the component when it's created (asynchronously).
     */
    public void setEventDispatcher(EventDispatcher eventDispatcher) {
        this.eventDispatcher = eventDispatcher;
        // Don't set it here - component might not exist yet
        // It will be set in initializeStatusBar() when component is created
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
                statusBarComponent = new DecompaiStatusBarComponent(tool);
                statusBarProvider = new DecompaiStatusBarProvider(tool, statusBarComponent);
                
                // Set event dispatcher on component (single place, when component is created)
                if (eventDispatcher != null) {
                    statusBarComponent.setEventDispatcher(eventDispatcher);
                    Msg.info(this, "StatusBarManager: Set event dispatcher on status bar component");
                } else {
                    Msg.warn(this, "StatusBarManager: eventDispatcher is null when creating component");
                }
                
                // Add unified status display to status bar
                windowManager.addStatusItem(statusBarComponent.getUnifiedStatusPanel(), true, true);
                
                // Try to find StatusBar for direct access (optional, for setStatusText)
                java.awt.Window rootWindow = tool.getActiveWindow();
                if (rootWindow == null) {
                    rootWindow = tool.getToolFrame();
                }
                if (rootWindow != null) {
                    statusBar = findStatusBarInWindow(rootWindow);
                }
                
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
     * Find StatusBar component in the window hierarchy.
     */
    private StatusBar findStatusBarInWindow(java.awt.Window window) {
        if (window == null) {
            return null;
        }
        
        if (window instanceof java.awt.Container) {
            return findStatusBar((java.awt.Container) window);
        }
        
        return null;
    }
    
    /**
     * Find StatusBar component in the container hierarchy.
     */
    private StatusBar findStatusBar(java.awt.Container container) {
        if (container == null) {
            return null;
        }
        
        if (container instanceof StatusBar) {
            return (StatusBar) container;
        }
        
        // Recursively search children
        for (java.awt.Component child : container.getComponents()) {
            if (child instanceof StatusBar) {
                return (StatusBar) child;
            }
            if (child instanceof java.awt.Container) {
                StatusBar found = findStatusBar((java.awt.Container) child);
                if (found != null) {
                    return found;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Register an active task with the status bar.
     * @param taskId Unique identifier for the task
     * @param priority Status bar priority (lower number = higher priority)
     */
    public void registerTask(String taskId, int priority) {
        activeTasks.put(taskId, new TaskStatus(taskId, priority));
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
            taskStatus.status = status != null ? status : "";
            taskStatus.progress = progress;
            taskStatus.indeterminate = indeterminate;
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
        SwingUtilities.invokeLater(() -> {
            if (statusBarComponent == null) {
                // Component not initialized yet - skip update
                return;
            }
            
            Optional<TaskStatus> activeTask = getActiveTask();
            
            if (activeTask.isPresent()) {
                TaskStatus task = activeTask.get();
                // Update unified status display with logo, status, and progress
                // Use empty string if status is null, but still show the panel
                statusBarComponent.updateUnifiedStatus(task.status, task.progress, task.indeterminate);
            } else {
                statusBarComponent.updateUnifiedStatus("Ready", null, false);
            }
        });
    }
    
    /**
     * Get the status bar component (for testing or advanced usage).
     */
    public DecompaiStatusBarComponent getComponent() {
        return statusBarComponent;
    }
    
    /**
     * Set the services reference to access current program for state checking.
     */
    public void setServices(com.zenyard.decompai.ghidra.DecompaiServices services) {
        this.services = services;
    }
    
}
