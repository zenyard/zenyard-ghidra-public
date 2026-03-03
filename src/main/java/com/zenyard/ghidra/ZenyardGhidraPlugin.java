package com.zenyard.ghidra;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.events.FirstTimeAnalyzedPluginEvent;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.options.Options;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.Swing;
// ProgramManagerListener removed in Ghidra 12.0 - ProgramPlugin handles program lifecycle

import com.zenyard.ghidra.api.generated.ApiClient;
import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.api.UserApi;
import com.zenyard.ghidra.config.EulaDialog;
import com.zenyard.ghidra.config.OnboardingDialog;
import com.zenyard.ghidra.config.ZenyardConfigFile;
import com.zenyard.ghidra.config.ZenyardOptions;
import com.zenyard.ghidra.config.LicenseConfigDialog;
import com.zenyard.ghidra.config.PluginConfiguration;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventConsumer;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.initialization.InitialUploadMessageDialog;
import com.zenyard.ghidra.initialization.AskInitialQuestionsTask;
import com.zenyard.ghidra.initialization.ShowInitialQuestionsTask;
import com.zenyard.ghidra.initialization.StartForegroundTasksTask;
import com.zenyard.ghidra.illum.FunctionListHighlighter;
import com.zenyard.ghidra.illum.SymbolTreeHighlighter;
import com.zenyard.ghidra.polling.ApplyInferencesTask;
import com.zenyard.ghidra.polling.DownloadInferencesTask;
import com.zenyard.ghidra.polling.PollServerStatusTask;
import com.zenyard.ghidra.polling.PollUsageTask;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.storage.SyncStatusStorage;
import com.zenyard.ghidra.status.StatusBarManager;
import com.zenyard.ghidra.status.StatusBarPriorities;
import com.zenyard.ghidra.ui.BinarySizeLimitDialog;
import com.zenyard.ghidra.ui.PythonUnavailableDialog;
import com.zenyard.ghidra.upload.QueueRevisionsTask;
import com.zenyard.ghidra.upload.RegisterBinaryTask;
import com.zenyard.ghidra.upload.UploadOriginalFilesTask;
import com.zenyard.ghidra.upload.UploadRevisionsTask;
import com.zenyard.ghidra.tracking.TrackChangesTaskManager;
import com.zenyard.ghidra.util.BinarySizeLimitGate;
import com.zenyard.ghidra.copilot.tools.RunPythonScriptTool;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Main plugin entry point for Zenyard Ghidra extension.
 * 
 * This plugin provides AI-powered reverse engineering assistance through
 * the Zenyard service, including:
 * - Illuminator: Function/variable highlighting and renaming
 * - Copilot: LLM-assisted chat interface
 * - Status bar integration for progress and errors
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "com.zenyard.ghidra",
    category = "Reverse Engineering",
    shortDescription = "Zenyard - AI-powered reverse engineering assistance",
    description = "In-depth binary understanding with a purpose built AI agent that helps you get straight to the meaningful parts and understand them faster.",
    eventsConsumed = { FirstTimeAnalyzedPluginEvent.class }
)
public class ZenyardGhidraPlugin extends ProgramPlugin implements EventConsumer {
    
    private static final String VARIADIC_SIGNATURE_OVERRIDE_ANALYZER =
        "Variadic Function Signature Override";

    private ZenyardOptions options;
    private ZenyardService services;
    private TrackChangesTaskManager trackChangesTaskManager;
    private ApplyInferencesTask applyInferencesTask; // Reference to continuous apply task
    private PollServerStatusTask pollServerStatusTask; // Provides connectivity + analysis status updates
    private static final String WAITING_FOR_GHIDRA_TASK_ID = "waiting_for_ghidra";
    private final Set<Program> scheduledSizeGates =
        Collections.newSetFromMap(new ConcurrentHashMap<>());
    
    public ZenyardGhidraPlugin(PluginTool tool) {
        super(tool);
        
        // Initialize options (reads from config file)
        this.options = new ZenyardOptions(tool);
        
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
            com.zenyard.ghidra.ZenyardService.clearInstance();
        }
        // ProgramManagerListener removed in Ghidra 12.0 - no need to unregister
        super.dispose();
    }
    
    @Override
    public void processEvent(PluginEvent event) {
        super.processEvent(event);

        if (event == null) {
            return;
        }

        // ProgramPlugin doesn't expose a dedicated "programClosing" callback in all
        // supported Ghidra versions. Listen for close/deactivate events so our
        // background tasks can bail out early during shutdown.
        String eventClass = event.getClass().getName();
        if (eventClass.contains("ProgramClosing")
            || eventClass.contains("ProgramClosed")
            || eventClass.contains("ProgramDeactivated")) {
            publishProgramDeactivatedEvent();
        }
        
        if (event instanceof FirstTimeAnalyzedPluginEvent) {
            FirstTimeAnalyzedPluginEvent ev = (FirstTimeAnalyzedPluginEvent) event;
            Msg.debug(this, "ZenyardGhidraPlugin: Received FirstTimeAnalyzedPluginEvent");
            Program program = ev.getProgram();
            if (program != null && program.equals(currentProgram)) {
                Swing.runLater(() -> handleAnalysisComplete(program));
            }    
        }
    }
    
    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);

        enableVariadicSignatureOverrideAnalyzer(program);
        
        // Initialize services when a program is activated (needed for status bar actions)
        if (services == null) {
            services = new ZenyardService(this, options);
        }

        // Gate extension activation on EULA acceptance
        if (!ensureEulaAccepted()) {
            return;
        }

        maybeShowPythonUnavailablePopup(program);
        activateForProgram(program);
    }

    private void maybeShowPythonUnavailablePopup(Program program) {
        if (program == null || program.isClosed() || options == null) {
            return;
        }
        if (!options.isShowPythonUnavailablePopup()) {
            return;
        }
        if (RunPythonScriptTool.isPythonAvailable()) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            Program activeProgram = getCurrentProgram();
            if (activeProgram == null || activeProgram.isClosed()) {
                return;
            }
            PythonUnavailableDialog dialog = new PythonUnavailableDialog(options);
            tool.showDialog(dialog);
        });
    }

    private void enableVariadicSignatureOverrideAnalyzer(Program program) {
        if (program == null || program.isClosed()) {
            return;
        }

        Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
        if (!analysisOptions.contains(VARIADIC_SIGNATURE_OVERRIDE_ANALYZER)) {
            Msg.warn(this,
                "Analyzer option not found: " + VARIADIC_SIGNATURE_OVERRIDE_ANALYZER);
            return;
        }

        if (analysisOptions.getBoolean(VARIADIC_SIGNATURE_OVERRIDE_ANALYZER, false)) {
            return;
        }

        int transactionId = program.startTransaction(
            "Enable variadic function signature override analyzer");
        boolean commit = false;
        try {
            analysisOptions.setBoolean(VARIADIC_SIGNATURE_OVERRIDE_ANALYZER, true);
            commit = true;
            Msg.info(this,
                "Enabled analyzer: " + VARIADIC_SIGNATURE_OVERRIDE_ANALYZER);
        } catch (RuntimeException e) {
            Msg.warn(this,
                "Failed to enable analyzer " + VARIADIC_SIGNATURE_OVERRIDE_ANALYZER, e);
        } finally {
            program.endTransaction(transactionId, commit);
        }
    }
    
    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);

        if (program != null) {
            scheduledSizeGates.remove(program);
        }
        
        publishProgramDeactivatedEvent();
        
        // Clear task reference (task will terminate via event)
        applyInferencesTask = null;

        // Stop poller (it will also terminate via PROGRAM_DEACTIVATED event)
        if (pollServerStatusTask != null) {
            pollServerStatusTask.stop();
            pollServerStatusTask = null;
        }
        
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
        if (program != null) {
            scheduledSizeGates.remove(program);
        }
        if (services != null) {
            services.onProgramClosed(program);
        }
    }

    private void publishProgramDeactivatedEvent() {
        // Publish PROGRAM_DEACTIVATED event to notify all active tasks
        if (services == null) {
            return;
        }
        EventDispatcher eventDispatcher = services.getEventDispatcher();
        if (eventDispatcher == null) {
            return;
        }
        ZenyardEvent event = new ZenyardEvent(ZenyardEvent.EventType.PROGRAM_DEACTIVATED, getName());
        eventDispatcher.publish(event);
    }
    
    private void createActions() {
        // Configuration action
        DockingAction configAction = new DockingAction("Zenyard Configuration", getName()) {
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
        configAction.setDescription("Configure Zenyard API key and server settings");
        tool.addAction(configAction);
        
        // Open Copilot action
        DockingAction copilotAction = new DockingAction("Open Copilot", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (services == null) {
                    services = new ZenyardService(ZenyardGhidraPlugin.this, options);
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
            new String[] { "Zenyard", "Copilot" },
            null,
            "Zenyard"
        ));
        copilotAction.setKeyBindingData(new KeyBindingData(
            javax.swing.KeyStroke.getKeyStroke(
                java.awt.event.KeyEvent.VK_C,
                java.awt.event.InputEvent.CTRL_DOWN_MASK | java.awt.event.InputEvent.ALT_DOWN_MASK
            )
        ));
        copilotAction.setDescription("Open the Zenyard Copilot chat window");
        tool.addAction(copilotAction);
    }
    
    private void showConfigurationDialog() {
        LicenseConfigDialog dialog = new LicenseConfigDialog(tool, options);
        tool.showDialog(dialog);
    }

    private void showConfigurationDialogIfNeeded() {
        if (!ZenyardConfigFile.configFileExists() && !options.isConfigured()) {
            SwingUtilities.invokeLater(this::showConfigurationDialog);
        }
    }

    public void activateAfterEulaAcceptance() {
        if (!options.isEulaAccepted(EulaDialog.EULA_VERSION)) {
            return;
        }
        if (services == null) {
            services = new ZenyardService(this, options);
        }
        if (trackChangesTaskManager != null) {
            return;
        }
        Program program = getCurrentProgram();
        if (program == null || program.isClosed()) {
            return;
        }
        activateForProgram(program);
    }

    private void activateForProgram(Program program) {
        if (services == null) {
            return;
        }
        if (trackChangesTaskManager != null) {
            return;
        }
        services.onProgramActivated(program);

        StatusBarManager statusBarManager = services.getStatusBarManager();
        // Start connectivity/status polling before applying the binary size gate.
        // Otherwise, a temporary server outage can block task startup and also prevent the
        // status bar from showing the connection warning icon.
        startStatusPollerIfPossible(program);
        scheduleBinarySizeGate(program, statusBarManager);
    }

    private void scheduleBinarySizeGate(Program program, StatusBarManager statusBarManager) {
        if (program == null || program.isClosed() || services == null) {
            return;
        }
        if (!scheduledSizeGates.add(program)) {
            return; // already scheduled for this program instance
        }

        // NOTE: programActivated runs on the Swing thread; never block it on network.
        Task gateTask = new Task("Zenyard Binary Size Gate", false, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    BinarySizeLimitGate.CheckResult sizeGateResult =
                        BinarySizeLimitGate.check(program, services.getUserApi());

                    // Program may be closed (database disposed) while we are waiting on network.
                    if (program.isClosed()) {
                        return;
                    }
                    try {
                        BinarySizeLimitGate.persistResult(program, sizeGateResult);
                    } catch (IllegalStateException e) {
                        // Ghidra can dispose the underlying DB handle during close; avoid surfacing
                        // noisy errors from a best-effort status check.
                        Msg.debug(ZenyardGhidraPlugin.this,
                            "Binary size gate: program DB closed before persisting result");
                        return;
                    } catch (RuntimeException e) {
                        // Same rationale: don't crash background worker if program is closing.
                        Msg.debug(ZenyardGhidraPlugin.this,
                            "Binary size gate: failed to persist result: " + e.getMessage());
                        return;
                    }

                    SwingUtilities.invokeLater(() -> {
                        if (program.isClosed() || program != currentProgram) {
                            return;
                        }
                        if (!sizeGateResult.isPassed()) {
                            if (statusBarManager != null) {
                                statusBarManager.refreshDisplayNow();
                            }
                            Msg.warn(ZenyardGhidraPlugin.this,
                                "Skipping Zenyard task startup: binary size gate did not pass: "
                                    + sizeGateResult.getMessage());
                            return;
                        }
                        activateAfterBinarySizeGate(program, statusBarManager);
                    });
                } finally {
                    scheduledSizeGates.remove(program);
                }
            }
        };
        executeBackgroundTask(gateTask);
    }

    private void activateAfterBinarySizeGate(Program program, StatusBarManager statusBarManager) {
        if (program == null || program.isClosed() || services == null) {
            return;
        }
        if (trackChangesTaskManager != null) {
            return;
        }

        EventDispatcher eventDispatcher = services.getEventDispatcher();
        eventDispatcher.subscribe(this);

        // Initialize track changes task manager with EventDispatcher
        trackChangesTaskManager = new TrackChangesTaskManager(tool, eventDispatcher);
        services.setTrackChangesTaskManager(trackChangesTaskManager);

        // Always start background tasks - they will check their own prerequisites
        BinariesApi binariesApi = services.getBinariesApi();
        if (binariesApi != null && statusBarManager != null) {
            startBackgroundTasks(program, binariesApi, statusBarManager);
        }

        // Show configuration dialog after EULA acceptance if needed
        showConfigurationDialogIfNeeded();

        // If the binary was analyzed before plugin activation/installation, FirstTimeAnalyzedPluginEvent
        // will not fire in this session. Reconcile persisted state now.
        reconcileAnalysisCompletionState(program);

        // Check if analysis is already complete (for programs analyzed before plugin activation)
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        String alreadyCompleted = props.getString("initial_analysis_complete");

        if (!"true".equals(alreadyCompleted)) {
            // Analysis not complete - register status bar task to show "Waiting for Ghidra"
            if (statusBarManager != null) {
                statusBarManager.registerTask(WAITING_FOR_GHIDRA_TASK_ID,
                    StatusBarPriorities.WAITING_FOR_GHIDRA);
                statusBarManager.updateTaskStatus(WAITING_FOR_GHIDRA_TASK_ID, "Waiting for Ghidra", null, true);
            }
        } else if (trackChangesTaskManager != null) {
            // Analysis already complete from a previous session.
            // Defer enabling the change tracker until Ghidra's auto-analysis on
            // re-open finishes; otherwise the tracker would mark functions dirty
            // from auto-analysis events, causing a partial initial upload.
            trackChangesTaskManager.setInitialAnalysisComplete(true);
            scheduleTrackingAfterAutoAnalysis(program);
        }

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

    private void reconcileAnalysisCompletionState(Program program) {
        if (program == null || program.isClosed()) {
            return;
        }

        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        if ("true".equals(props.getString("initial_analysis_complete"))) {
            return;
        }

        if (GhidraProgramUtilities.isAnalyzed(program)) {
            Msg.info(this, "Program already analyzed; marking initial_analysis_complete for activation recovery");
            handleAnalysisComplete(program);
        }
    }

    private boolean ensureEulaAccepted() {
        if (options.isEulaAccepted(EulaDialog.EULA_VERSION)) {
            return true;
        }
        boolean accepted = OnboardingDialog.showDialog(tool, options);
        int acceptedVersion = accepted ? EulaDialog.EULA_VERSION : -1;
        try {
            options.updateConfiguration(Map.of("accepted_eula_version", acceptedVersion));
        } catch (java.io.IOException e) {
            Msg.showError(this, tool.getActiveWindow(), "Configuration Error",
                "Failed to update EULA acceptance in zenyard.json", e);
        }
        if (services != null && services.getStatusBarManager() != null) {
            services.getStatusBarManager().refreshDisplayNow();
        }
        if (!accepted) {
            return false;
        }
        try {
            if (!ZenyardConfigFile.configFileExists()) {
                ZenyardConfigFile.writeConfiguration(PluginConfiguration.getDefault());
                options.reloadConfiguration();
            }
        } catch (java.io.IOException e) {
            Msg.showError(this, tool.getActiveWindow(), "Configuration Error",
                "Failed to create default zenyard.json", e);
            return false;
        }
        if (!options.isConfigured()) {
            showConfigurationDialog();
        }
        return options.isConfigured();
    }
    
    public ZenyardOptions getOptions() {
        return options;
    }
    
    public ZenyardService getServices() {
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
        ApiClient apiClient = services.getApiClient();
        UserApi userApi = services.getUserApi();
        if (apiClient == null) {
            Msg.debug(this, "PollServerStatusTask: ApiClient unavailable, skipping poller startup");
            return;
        }
        
        // Start polling server status (will wait for binary_id internally).
        // The poller may have been started before the binary-size gate runs; avoid duplicating it.
        startStatusPollerIfPossible(program);

        if (userApi != null) {
            PollUsageTask pollUsageTask = new PollUsageTask(
                userApi, services, eventDispatcher);
            executeBackgroundTask(pollUsageTask);
        }
        
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

    private void startStatusPollerIfPossible(Program program) {
        if (program == null || program.isClosed() || services == null) {
            return;
        }
        if (pollServerStatusTask != null) {
            return;
        }

        EventDispatcher eventDispatcher = services.getEventDispatcher();
        ApiClient apiClient = services.getApiClient();
        if (eventDispatcher == null) {
            Msg.debug(this, "PollServerStatusTask: EventDispatcher unavailable, skipping poller startup");
            return;
        }
        if (apiClient == null) {
            Msg.debug(this, "PollServerStatusTask: ApiClient unavailable, skipping poller startup");
            return;
        }

        pollServerStatusTask = new PollServerStatusTask(tool, apiClient, program, eventDispatcher);
        executeBackgroundTask(pollServerStatusTask);
    }
    
    /**
     * Initialize sync status for all objects on first upload.
     * Called when event is received.
     */
    private void handleInitialUploadComplete(Program program) {
        if (program == null || program.isClosed()) {
            return;
        }
        
        ZenyardProgramProperties uploadProps = new ZenyardProgramProperties(program);
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
        com.zenyard.ghidra.storage.SyncStatusStorage syncStatusStorage = 
            new com.zenyard.ghidra.storage.SyncStatusStorage(program);
        
        // Get all object symbols
        List<com.zenyard.ghidra.util.ObjectGraph.Symbol> symbols = 
            com.zenyard.ghidra.util.ObjectReader.getAllObjectSymbols(program);
        
        // Mark all as dirty
        for (com.zenyard.ghidra.util.ObjectGraph.Symbol symbol : symbols) {
            syncStatusStorage.markDirty(symbol.getAddress());
        }
        
        // Set database_dirty flag
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        props.setString("database_dirty", "true");
        
    }
    
    /**
     * Schedule enabling the change tracker after Ghidra's auto-analysis finishes.
     * When a previously-analyzed program is re-opened, Ghidra runs a short
     * auto-analysis pass that fires domain-object events. If the change tracker
     * is already active, those events cause a partial dirty-address set, which
     * in turn leads to an incomplete initial upload.  By deferring until
     * auto-analysis completes, only genuine user-initiated changes are tracked.
     */
    private void scheduleTrackingAfterAutoAnalysis(Program program) {
        Task task = new Task("Enable Change Tracking", false, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    AutoAnalysisManager analysisManager =
                        AutoAnalysisManager.getAnalysisManager(program);
                    // Block until Ghidra's auto-analysis on re-open finishes.
                    analysisManager.waitForAnalysis(30_000, monitor);
                } catch (Exception e) {
                    Msg.warn(ZenyardGhidraPlugin.this,
                        "Error waiting for auto-analysis: " + e.getMessage());
                }
                if (trackChangesTaskManager != null
                        && !program.isClosed()
                        && !monitor.isCancelled()) {
                    trackChangesTaskManager.enableTrackingAfterInitialization();
                    Msg.info(ZenyardGhidraPlugin.this,
                        "Change tracking enabled after auto-analysis completed");
                }
            }
        };
        executeBackgroundTask(task);
    }

    /**
     * Handle analysis completion when FirstTimeAnalyzedPluginEvent is received.
     * Sets the initial_analysis_complete property, unregisters status bar task, and notifies waiting tasks.
     */
    private void handleAnalysisComplete(Program program) {
        if (program == null || program.isClosed()) {
            return;
        }
        
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        
        // Check if we've already marked it as complete (avoid duplicate notifications)
        String alreadyCompleted = props.getString("initial_analysis_complete");
        if ("true".equals(alreadyCompleted)) {
            return;
        }
        
        // Mark as complete
        props.setString("initial_analysis_complete", "true");

        // If binary exceeded plan size, show that one-time popup now (instead of initial questions flow).
        if ("true".equals(props.getString(BinarySizeLimitGate.PROP_BINARY_SIZE_LIMIT_EXCEEDED))) {
            Integer maxSizeMb = props.getInt(BinarySizeLimitGate.PROP_BINARY_SIZE_LIMIT_MB);
            if (maxSizeMb != null && maxSizeMb > 0) {
                BinarySizeLimitDialog.showDialogIfNeeded(tool, program, maxSizeMb);
            }
            return;
        }
        
        // Unregister from status bar
        if (services != null) {
            StatusBarManager statusBarManager = services.getStatusBarManager();
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(WAITING_FOR_GHIDRA_TASK_ID);
            }
            
            // Publish ANALYSIS_COMPLETE event
            EventDispatcher eventDispatcher = services.getEventDispatcher();
            if (eventDispatcher != null) {
                ZenyardEvent event = new ZenyardEvent(ZenyardEvent.EventType.ANALYSIS_COMPLETE, getName());
                eventDispatcher.publish(event);
            }
        }
        if (trackChangesTaskManager != null) {
            trackChangesTaskManager.setInitialAnalysisComplete(true);
            trackChangesTaskManager.enableTrackingAfterInitialization();
        }
    }

    
    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        Set<ZenyardEvent.EventType> types = new HashSet<>();
        types.add(ZenyardEvent.EventType.INITIAL_UPLOAD_COMPLETE);
        return types;
    }
    
    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.INITIAL_UPLOAD_COMPLETE) {
            Msg.info(this, "ZenyardGhidraPlugin: Received INITIAL_UPLOAD_COMPLETE event");
            // Show InitialUploadMessageDialog after upload completes
            SwingUtilities.invokeLater(() -> {
                if (currentProgram != null && !currentProgram.isClosed()) {
                    handleInitialUploadComplete(currentProgram);
                } else {
                    Msg.warn(this, "ZenyardGhidraPlugin: Cannot show dialog - program is null or closed");
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
                Msg.error(ZenyardGhidraPlugin.class, "Error executing background task: " + task.getTaskTitle(), e);
            }
        });
        taskThread.setDaemon(true);
        taskThread.start();
    }
}
