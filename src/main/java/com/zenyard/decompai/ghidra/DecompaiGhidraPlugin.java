package com.zenyard.decompai.ghidra;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.events.FirstTimeAnalyzedPluginEvent;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
// ProgramManagerListener removed in Ghidra 12.0 - ProgramPlugin handles program lifecycle

import com.zenyard.decompai.ghidra.api.generated.api.BinariesApi;
import com.zenyard.decompai.ghidra.config.DecompaiConfigFile;
import com.zenyard.decompai.ghidra.config.DecompaiOptions;
import com.zenyard.decompai.ghidra.config.LicenseConfigDialog;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.events.EventConsumer;
import com.zenyard.decompai.ghidra.events.EventDispatcher;
import com.zenyard.decompai.ghidra.initialization.InitialUploadMessageDialog;
import com.zenyard.decompai.ghidra.initialization.AskInitialQuestionsTask;
import com.zenyard.decompai.ghidra.initialization.ShowInitialQuestionsTask;
import com.zenyard.decompai.ghidra.initialization.StartForegroundTasksTask;
import com.zenyard.decompai.ghidra.illum.FunctionListHighlighter;
import com.zenyard.decompai.ghidra.illum.SymbolTreeHighlighter;
import com.zenyard.decompai.ghidra.polling.ApplyInferencesTask;
import com.zenyard.decompai.ghidra.polling.DownloadInferencesTask;
import com.zenyard.decompai.ghidra.polling.PollServerStatusTask;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;
import com.zenyard.decompai.ghidra.storage.SyncStatusStorage;
import com.zenyard.decompai.ghidra.status.StatusBarManager;
import com.zenyard.decompai.ghidra.status.StatusBarPriorities;
import com.zenyard.decompai.ghidra.upload.QueueRevisionsTask;
import com.zenyard.decompai.ghidra.upload.RegisterBinaryTask;
import com.zenyard.decompai.ghidra.upload.UploadOriginalFilesTask;
import com.zenyard.decompai.ghidra.upload.UploadRevisionsTask;
import com.zenyard.decompai.ghidra.tracking.TrackChangesTaskManager;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Main plugin entry point for DecompAI Ghidra extension.
 * 
 * This plugin provides AI-powered reverse engineering assistance through
 * the DecompAI service, including:
 * - Illuminator: Function/variable highlighting and renaming
 * - Copilot: LLM-assisted chat interface
 * - Status bar integration for progress and errors
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "com.zenyard.decompai.ghidra",
    category = "Reverse Engineering",
    shortDescription = "DecompAI - AI-powered reverse engineering assistance",
    description = "Provides AI-powered reverse engineering assistance through the DecompAI service. " 
                  + "Features include function/variable highlighting, renaming, and LLM-assisted analysis.",
    eventsConsumed = { FirstTimeAnalyzedPluginEvent.class }
)
public class DecompaiGhidraPlugin extends ProgramPlugin implements EventConsumer {
    
    private DecompaiOptions options;
    private DecompaiServices services;
    private TrackChangesTaskManager trackChangesTaskManager;
    private ApplyInferencesTask applyInferencesTask; // Reference to continuous apply task
    private static final String WAITING_FOR_GHIDRA_TASK_ID = "waiting_for_ghidra";
    
    public DecompaiGhidraPlugin(PluginTool tool) {
        super(tool);
        
        // Initialize options (reads from config file)
        this.options = new DecompaiOptions(tool);
        
        // If config file doesn't exist and API key is empty, show config dialog
        if (!DecompaiConfigFile.configFileExists() && !options.isConfigured()) {
            SwingUtilities.invokeLater(() -> {
                showConfigurationDialog();
            });
        }
        
        // Initialize services (will be created when program is opened)
        this.services = null;
        
        // Initialize track changes task manager (will be initialized with EventDispatcher when services are created)
        this.trackChangesTaskManager = null; // Will be set when services are initialized
        
        // Register actions
        createActions();

        SwingUtilities.invokeLater(() -> {
            FunctionListHighlighter.installRenderer(tool);
            SymbolTreeHighlighter.installRenderer(tool);
        });
    }
    
    @Override
    public void dispose() {
        // Unsubscribe from events
        if (services != null && services.getEventDispatcher() != null) {
            services.getEventDispatcher().unsubscribe(this);
        }

        if (services != null && services.getStatusBarManager() != null) {
            services.getStatusBarManager().dispose();
        }
        
        // Clear singleton instance when plugin is disposed
        if (services != null) {
            com.zenyard.decompai.ghidra.DecompaiServices.clearInstance();
        }
        // ProgramManagerListener removed in Ghidra 12.0 - no need to unregister
        super.dispose();
    }
    
    @Override
    public void processEvent(PluginEvent event) {
        super.processEvent(event);
        
        if (event instanceof FirstTimeAnalyzedPluginEvent) {
            FirstTimeAnalyzedPluginEvent ev = (FirstTimeAnalyzedPluginEvent) event;
            Program program = ev.getProgram();
            if (program != null && program.equals(currentProgram)) {
                Swing.runLater(() -> handleAnalysisComplete(program));
            }
        }
    }
    
    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        
        // Initialize services when a program is activated
        if (services == null) {
            services = new DecompaiServices(this, options);
        }
        
        services.onProgramActivated(program);
        
        EventDispatcher eventDispatcher = services.getEventDispatcher();
        eventDispatcher.subscribe(this);

        // Initialize track changes task manager with EventDispatcher
        trackChangesTaskManager = new TrackChangesTaskManager(tool, eventDispatcher);
        if (services != null) {
            services.setTrackChangesTaskManager(trackChangesTaskManager);
        }
        
        // Always start background tasks - they will check their own prerequisites
        BinariesApi binariesApi = services.getBinariesApi();
        StatusBarManager statusBarManager = services.getStatusBarManager();
        if (binariesApi != null && statusBarManager != null) {
            startBackgroundTasks(program, binariesApi, statusBarManager);
        }
        
        // Check if analysis is already complete (for programs analyzed before plugin activation)
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        String alreadyCompleted = props.getString("initial_analysis_complete");
        
        if (!"true".equals(alreadyCompleted)) {
            // // Check if program has already been analyzed
            // if (GhidraProgramUtilities.isAnalyzed(program)) {
            //     // Program was already analyzed - mark as complete and notify immediately
            //     handleAnalysisComplete(program);
            // } else {
                // Analysis not complete - register status bar task to show "Waiting for Ghidra"
                if (statusBarManager != null) {
                    statusBarManager.registerTask(WAITING_FOR_GHIDRA_TASK_ID, 
                        StatusBarPriorities.WAITING_FOR_GHIDRA);
                    statusBarManager.updateTaskStatus(WAITING_FOR_GHIDRA_TASK_ID, "Waiting for Ghidra", null, true);
                }
            // }
        } else if (trackChangesTaskManager != null) {
            // Analysis already complete from a previous session; re-enable change tracking.
            trackChangesTaskManager.setInitialAnalysisComplete(true);
            trackChangesTaskManager.setIgnoreEvents(false);
        }
        
        // Always start all initialization tasks - they will check their own state and prerequisites
        // Tasks will handle their own state checking and use events for prerequisites
        
        // 1. AskInitialQuestionsTask - waits for ANALYSIS_COMPLETE, publishes READY_FOR_QUESTIONS
        AskInitialQuestionsTask askQuestionsTask = new AskInitialQuestionsTask(
            tool, program, services);
        executeBackgroundTask(askQuestionsTask);
        
        // 2. ShowInitialQuestionsTask - waits for READY_FOR_QUESTIONS, publishes INITIAL_DIALOG_CONFIRMED
        ShowInitialQuestionsTask showQuestionsTask = new ShowInitialQuestionsTask(
            tool, program, services);
        executeBackgroundTask(showQuestionsTask);
        
        // 3. StartForegroundTasksTask - processes foreground task queue (may be removed later)
        StartForegroundTasksTask startForegroundTasksTask = new StartForegroundTasksTask(
            tool, program, services);
        executeBackgroundTask(startForegroundTasksTask);
        
        // 4. RegisterBinaryTask - start it unconditionally
        // It will check if already registered and wait for prerequisites (ANALYSIS_COMPLETE + INITIAL_DIALOG_CONFIRMED events)
        // Publishes BINARY_REGISTERED and BINARY_ID_AVAILABLE events on completion
        if (binariesApi != null && statusBarManager != null) {
            RegisterBinaryTask registerTask = new RegisterBinaryTask(
                tool, binariesApi, options, null, statusBarManager, program, services);
            executeBackgroundTask(registerTask);
        }
    }
    
    
    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
        
        // Publish PROGRAM_DEACTIVATED event to notify all active tasks
        if (services != null) {
            EventDispatcher eventDispatcher = services.getEventDispatcher();
            if (eventDispatcher != null) {
                DecompaiEvent event = new DecompaiEvent(DecompaiEvent.EventType.PROGRAM_DEACTIVATED, getName());
                eventDispatcher.publish(event);
            }
        }
        
        // Clear task reference (task will terminate via event)
        applyInferencesTask = null;
        
        // Stop tracking changes for this program
        if (trackChangesTaskManager != null) {
            trackChangesTaskManager.stop();
        }
        
        // Unregister status bar task if registered
        if (services != null) {
            StatusBarManager statusBarManager = services.getStatusBarManager();
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(WAITING_FOR_GHIDRA_TASK_ID);
            }
            services.onProgramDeactivated(program);
        }
    }
    
    @Override
    protected void programClosed(Program program) {
        super.programClosed(program);
        
        if (services != null) {
            services.onProgramClosed(program);
        }
    }
    
    private void createActions() {
        // Configuration action
        DockingAction configAction = new DockingAction("DecompAI Configuration", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                showConfigurationDialog();
            }
        };
        configAction.setMenuBarData(new MenuData(
            new String[] { "Zenyard", "Configuration..." },
            null,
            "Zenyard"
        ));
        configAction.setDescription("Configure DecompAI API key and server settings");
        tool.addAction(configAction);
        
        // Open Copilot action
        DockingAction copilotAction = new DockingAction("Open Copilot", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (services == null) {
                    services = new DecompaiServices(DecompaiGhidraPlugin.this, options);
                    Program program = getCurrentProgram();
                    if (program != null) {
                        services.onProgramActivated(program);
                    }
                }
                if (services != null && services.getCopilotProvider() != null) {
                    try {
                        tool.addComponentProvider(services.getCopilotProvider(), false);
                    } catch (ghidra.util.exception.AssertException e) {
                        // Provider already added; ignore duplicate registration.
                    }
                    tool.showComponentProvider(services.getCopilotProvider(), true);
                }
            }
        };
        copilotAction.setMenuBarData(new MenuData(
            new String[] { "Zenyard", "Open Copilot" },
            null,
            "Zenyard"
        ));
        copilotAction.setDescription("Open the Zenyard Copilot chat window");
        tool.addAction(copilotAction);
    }
    
    private void showConfigurationDialog() {
        LicenseConfigDialog dialog = new LicenseConfigDialog(tool, options);
        tool.showDialog(dialog);
    }
    
    public DecompaiOptions getOptions() {
        return options;
    }
    
    public DecompaiServices getServices() {
        return services;
    }
    
    
    /**
     * Start background tasks for polling, downloading, and tracking changes.
     * This method is called unconditionally when a program is activated.
     * Tasks will check their own prerequisites (e.g., wait for binary_id) internally.
     */
    private void startBackgroundTasks(Program program, BinariesApi binariesApi, StatusBarManager statusBarManager) {
        if (program == null || program.isClosed()) {
            return;
        }
        
        // Create inference queue for downloading and applying inferences
        DownloadInferencesTask.InferenceQueue inferenceQueue = 
            new DownloadInferencesTask.InferenceQueue();
        
        // Start tracking changes for this program
        if (trackChangesTaskManager != null && statusBarManager != null) {
            SyncStatusStorage syncStatusStorage = new SyncStatusStorage(program);
            trackChangesTaskManager.start(program, syncStatusStorage);
        }

        // Get event dispatcher
        EventDispatcher eventDispatcher = services.getEventDispatcher();
        
        // Start polling server status (will wait for binary_id internally)
        PollServerStatusTask pollStatusTask = new PollServerStatusTask(
            tool, binariesApi, program, eventDispatcher);
        executeBackgroundTask(pollStatusTask);
        
        // Start continuous ApplyInferencesTask that waits for NEW_INFERENCES_AVAILABLE events
        applyInferencesTask = new ApplyInferencesTask(
            tool, inferenceQueue, trackChangesTaskManager, statusBarManager, program, eventDispatcher);
        executeBackgroundTask(applyInferencesTask);
        
        // Start downloading inferences (will wait for BINARY_ID_AVAILABLE event)
        DownloadInferencesTask downloadInferencesTask = new DownloadInferencesTask(
            tool, binariesApi, inferenceQueue, statusBarManager, program, eventDispatcher);
        executeBackgroundTask(downloadInferencesTask);
        
        // Start upload tasks - they will wait for events
        // UploadOriginalFilesTask waits for BINARY_REGISTERED event
        UploadOriginalFilesTask uploadFilesTask = new UploadOriginalFilesTask(
            tool, binariesApi, statusBarManager, program, eventDispatcher);
        executeBackgroundTask(uploadFilesTask);
        
        QueueRevisionsTask queueRevisionsTask = new QueueRevisionsTask(
            tool, program, statusBarManager, eventDispatcher);
        executeBackgroundTask(queueRevisionsTask);
        
        // UploadRevisionsTask waits for REVISIONS_QUEUED event
        UploadRevisionsTask uploadRevisionsTask = new UploadRevisionsTask(
            tool, binariesApi, statusBarManager, program, eventDispatcher);
        executeBackgroundTask(uploadRevisionsTask);
    }
    
    /**
     * Initialize sync status for all objects on first upload.
     * Called when event is received.
     */
    private void handleInitialUploadComplete(Program program) {
        if (program == null || program.isClosed()) {
            return;
        }
        
        DecompaiProgramProperties uploadProps = new DecompaiProgramProperties(program);
        String uploaded = uploadProps.getString("initial_upload_complete");
        boolean isInitialUpload = !"true".equals(uploaded);
        
        if (isInitialUpload) {
            initializeSyncStatus(program);
        }
        
        // Show InitialUploadMessageDialog after upload completes
        // The dialog will check if upload is complete and if it was already shown
        InitialUploadMessageDialog.showDialogIfNeeded(tool, options, program);
    }
    
    /**
     * Get the TrackChangesTaskManager instance.
     */
    public TrackChangesTaskManager getTrackChangesTaskManager() {
        return trackChangesTaskManager;
    }
    
    /**
     * Initialize sync status for all objects, marking them as dirty for initial upload.
     */
    private void initializeSyncStatus(Program program) {
        com.zenyard.decompai.ghidra.storage.SyncStatusStorage syncStatusStorage = 
            new com.zenyard.decompai.ghidra.storage.SyncStatusStorage(program);
        
        // Get all object symbols
        List<com.zenyard.decompai.ghidra.util.ObjectGraph.Symbol> symbols = 
            com.zenyard.decompai.ghidra.util.ObjectReader.getAllObjectSymbols(program);
        
        // Mark all as dirty
        for (com.zenyard.decompai.ghidra.util.ObjectGraph.Symbol symbol : symbols) {
            syncStatusStorage.markDirty(symbol.getAddress());
        }
        
        // Set database_dirty flag
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        props.setString("database_dirty", "true");
        
    }
    
    /**
     * Handle analysis completion when FirstTimeAnalyzedPluginEvent is received.
     * Sets the initial_analysis_complete property, unregisters status bar task, and notifies waiting tasks.
     */
    private void handleAnalysisComplete(Program program) {
        if (program == null || program.isClosed()) {
            return;
        }
        
        waitForAnalysisCompletion(program);

        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        
        // Check if we've already marked it as complete (avoid duplicate notifications)
        String alreadyCompleted = props.getString("initial_analysis_complete");
        if ("true".equals(alreadyCompleted)) {
            return;
        }
        
        // Mark as complete
        props.setString("initial_analysis_complete", "true");
        
        // Unregister from status bar
        if (services != null) {
            StatusBarManager statusBarManager = services.getStatusBarManager();
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(WAITING_FOR_GHIDRA_TASK_ID);
            }
            
            // Publish ANALYSIS_COMPLETE event
            EventDispatcher eventDispatcher = services.getEventDispatcher();
            if (eventDispatcher != null) {
                DecompaiEvent event = new DecompaiEvent(DecompaiEvent.EventType.ANALYSIS_COMPLETE, getName());
                eventDispatcher.publish(event);
            }
        }
        if (trackChangesTaskManager != null) {
            trackChangesTaskManager.setInitialAnalysisComplete(true);
            trackChangesTaskManager.setIgnoreEvents(false);
        }
    }

    private void waitForAnalysisCompletion(Program program) {
        AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
        if (analysisManager == null) {
            return;
        }

        Msg.debug(this, "Waiting for analysis completion");
        while (analysisManager.isAnalyzing() && !program.isClosed()) {
            try {
                Thread.sleep(250);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        Msg.debug(this, "Analysis completion complete");
    }
    
    @Override
    public Set<DecompaiEvent.EventType> getSubscribedEventTypes() {
        Set<DecompaiEvent.EventType> types = new HashSet<>();
        types.add(DecompaiEvent.EventType.INITIAL_UPLOAD_COMPLETE);
        return types;
    }
    
    @Override
    public void handleEvent(DecompaiEvent event) {
        if (event.getType() == DecompaiEvent.EventType.INITIAL_UPLOAD_COMPLETE) {
            Msg.info(this, "DecompaiGhidraPlugin: Received INITIAL_UPLOAD_COMPLETE event");
            // Show InitialUploadMessageDialog after upload completes
            SwingUtilities.invokeLater(() -> {
                if (currentProgram != null && !currentProgram.isClosed()) {
                    handleInitialUploadComplete(currentProgram);
                } else {
                    Msg.warn(this, "DecompaiGhidraPlugin: Cannot show dialog - program is null or closed");
                }
            });
        }
    }
    
    /**
     * Execute a task in a background thread without showing a dialog.
     * This is used for background tasks that should only show status in the status bar.
     */
    public static void executeBackgroundTask(Task task) {
        // Create a simple TaskMonitor that doesn't show a dialog
        TaskMonitor monitor = TaskMonitor.DUMMY;
        
        String threadName = "Background Task - " + task.getTaskTitle();
        Thread taskThread = new Thread(() -> {
            Thread.currentThread().setName(threadName);
            try {
                task.monitoredRun(monitor);
            } catch (Exception e) {
                Msg.error(DecompaiGhidraPlugin.class, "Error executing background task: " + task.getTaskTitle(), e);
            }
        });
        taskThread.setDaemon(true);
        taskThread.start();
    }
}

