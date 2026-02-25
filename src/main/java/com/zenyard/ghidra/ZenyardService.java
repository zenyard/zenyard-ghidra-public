package com.zenyard.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import com.zenyard.ghidra.api.ZenyardApiClientFactory;
import com.zenyard.ghidra.api.generated.ApiClient;
import com.zenyard.ghidra.api.generated.ApiException;
import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.api.UserApi;
import com.zenyard.ghidra.copilot.CopilotConfig;
import com.zenyard.ghidra.copilot.CopilotConfigMapper;
import com.zenyard.ghidra.config.EulaDialog;
import com.zenyard.ghidra.config.OnboardingDialog;
import com.zenyard.ghidra.config.ZenyardOptions;
import com.zenyard.ghidra.copilot.CopilotController;
import com.zenyard.ghidra.copilot.CopilotProvider;
import com.zenyard.ghidra.copilot.CopilotViewModel;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.illum.IlluminatorController;
import com.zenyard.ghidra.initialization.InitialQuestionsDialog;
import com.zenyard.ghidra.status.AnalysisProgressMonitor;
import com.zenyard.ghidra.status.QueuePositionMonitor;
import com.zenyard.ghidra.status.StatusBarActions;
import com.zenyard.ghidra.status.StatusBarManager;
import com.zenyard.ghidra.status.StatusBarState;
import com.zenyard.ghidra.status.StatusBarViewModel;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.tracking.TrackChangesTaskManager;
import com.zenyard.ghidra.tasks.ForegroundTask;
import com.zenyard.ghidra.ui.UsageDetailsDialog;
import com.zenyard.ghidra.upload.QueueRevisionsTask;
import com.zenyard.ghidra.upload.UploadRevisionsTask;
import com.zenyard.ghidra.usage.UsageState;
import com.zenyard.ghidra.util.LoggerUtil;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.events.EventConsumer;

import javax.swing.SwingUtilities;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Service registry / façade that provides access to Illuminator, Copilot,
 * status bar, configuration, and the API client.
 * 
 * Similar to IDA's TaskContext and GlobalTaskContext but adapted for Java/Ghidra.
 * 
 * This class is a singleton - use getInstance() to get the current instance,
 * or use static methods like getProgram() to access services.
 */
public class ZenyardService {
    
    private static ZenyardService instance;
    
    private final ZenyardGhidraPlugin plugin;
    private final ZenyardOptions options;
    private Program currentProgram;
    
    private ApiClient apiClient;
    private BinariesApi binariesApi;
    private UserApi userApi;
    @SuppressWarnings("unused")
    private IlluminatorController illuminatorController;
    private CopilotProvider copilotProvider;
    private CopilotController copilotController;
    private CopilotViewModel copilotViewModel;
    private StatusBarManager statusBarManager;
    private TrackChangesTaskManager trackChangesTaskManager;
    private EventDispatcher eventDispatcher;
    private AnalysisProgressMonitor analysisProgressMonitor;
    private QueuePositionMonitor queuePositionMonitor;
    private volatile boolean userConfigFetchInFlight;
    private volatile boolean userConfigFetched;
    private volatile long lastUserConfigFetchAttemptMs;
    private static final long USER_CONFIG_RETRY_MIN_INTERVAL_MS = 10_000L;
    private volatile UsageState usageState = UsageState.unknown();
    private volatile boolean serverConnected = true;
    private final EventConsumer serverConnectivityConsumer = new EventConsumer() {
        @Override
        public void handleEvent(ZenyardEvent event) {
            if (event == null || event.getType() != ZenyardEvent.EventType.SERVER_CONNECTIVITY_CHANGED) {
                return;
            }
            Boolean connected = event.getPayloadValue("connected", Boolean.class);
            if (connected == null) {
                return;
            }
            setServerConnected(connected.booleanValue());
        }

        @Override
        public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
            Set<ZenyardEvent.EventType> types = new HashSet<>();
            types.add(ZenyardEvent.EventType.SERVER_CONNECTIVITY_CHANGED);
            return types;
        }
    };
    
    // Foreground task queue infrastructure
    private final Deque<ForegroundTask> foregroundTaskQueue = new ArrayDeque<>();
    private final ReentrantLock queueLock = new ReentrantLock();
    private volatile boolean foregroundTaskActive = false;
    private final Object queueNotification = new Object();
    
    public ZenyardService(ZenyardGhidraPlugin plugin, ZenyardOptions options) {
        this.plugin = plugin;
        this.options = options;
        this.currentProgram = null;
        
        // Set singleton instance
        instance = this;
        
        // Initialize API client if configured
        if (options.isConfigured()) {
            this.apiClient = ZenyardApiClientFactory.createApiClient(options);
            this.binariesApi = new BinariesApi(apiClient);
            this.userApi = new UserApi(apiClient);
        }
        
        // Initialize event dispatcher first (needed by status bar manager and other components)
        this.eventDispatcher = new EventDispatcher();
        
        // Initialize status bar manager
        this.statusBarManager = new StatusBarManager(plugin.getTool());
        // Set event dispatcher so status bar component can subscribe to events
        this.statusBarManager.setEventDispatcher(eventDispatcher);
        this.statusBarManager.setActions(createStatusBarActions());
        
        // Track changes task manager is initialized by the plugin when a program is activated
        this.trackChangesTaskManager = null;
        
        // Initialize analysis progress monitor
        this.analysisProgressMonitor = new AnalysisProgressMonitor(statusBarManager, eventDispatcher);
        // Initialize queue position monitor
        this.queuePositionMonitor = new QueuePositionMonitor(statusBarManager, eventDispatcher);
        // Keep a service-level connectivity flag for UI consumers (e.g. Copilot send button).
        // This is updated by PollServerStatusTask / DownloadInferencesTask via SERVER_CONNECTIVITY_CHANGED.
        eventDispatcher.subscribe(serverConnectivityConsumer);
        
        // Initialize Copilot (controller exists even if API is not configured)
        this.copilotController = null;
        this.copilotViewModel = new CopilotViewModel();
        this.copilotProvider = new CopilotProvider(plugin.getTool(), null);
        this.copilotProvider.setViewModel(copilotViewModel);
        this.copilotController = new CopilotController(
            copilotProvider,
            apiClient,
            binariesApi,
            userApi,
            plugin.getTool()
        );
        this.copilotController.setViewModel(copilotViewModel);
        copilotProvider.setController(copilotController);
        Msg.info(this, "Copilot controller initialized in services constructor");
        if (apiClient != null && binariesApi != null && userApi != null) {
            fetchUserConfigAsync(false);
        }
        plugin.getTool().addComponentProvider(copilotProvider, false);
        plugin.getTool().getWindowManager().showComponentHeader(copilotProvider, false);
        
        // Illuminator will be initialized when program is activated
    }

    public void onProgramActivated(Program program) {
        this.currentProgram = program;
        
        // Configure logging for this program
        LoggerUtil.configureForProgram(program.getName(), options.getLogLevel());
        
        // Initialize API client if not already initialized
        if (apiClient == null && options.isConfigured()) {
            apiClient = ZenyardApiClientFactory.createApiClient(options);
            binariesApi = new BinariesApi(apiClient);
            userApi = new UserApi(apiClient);
            fetchUserConfigAsync(false);
        }
        
        // Initialize Illuminator
        if (apiClient != null) {
            illuminatorController = new IlluminatorController(plugin.getTool(), binariesApi, options);
        }
        
        if (copilotController != null) {
            copilotController.setCurrentProgram(program);
        }
    }
    
    public void onProgramDeactivated(Program program) {
        // Cleanup per-program services
    }
    
    public void onProgramClosed(Program program) {
        this.currentProgram = null;
        
        if (copilotController != null) {
            copilotController.setCurrentProgram(null);
        }
    }

    private void fetchUserConfigAsync(boolean force) {
        if (userApi == null || copilotController == null) {
            return;
        }
        if (!force && userConfigFetched) {
            return;
        }
        if (userConfigFetchInFlight) {
            return;
        }
        long now = System.currentTimeMillis();
        if (!force && lastUserConfigFetchAttemptMs > 0
                && now - lastUserConfigFetchAttemptMs < USER_CONFIG_RETRY_MIN_INTERVAL_MS) {
            return;
        }
        lastUserConfigFetchAttemptMs = now;
        userConfigFetchInFlight = true;
        CompletableFuture.supplyAsync(() -> {
            try {
                return userApi.getUserConfig();
            } catch (ApiException e) {
                throw new RuntimeException(e);
            }
        }).thenAccept(userConfig -> {
            try {
                if (userConfig == null) {
                    return;
                }
                userConfigFetched = true;
                CopilotConfig config = CopilotConfigMapper.fromUserConfig(userConfig);
                if (config != null && copilotController != null) {
                    copilotController.setCopilotConfig(sanitizeCopilotConfig(config));
                }
            } finally {
                userConfigFetchInFlight = false;
            }
        }).exceptionally(error -> {
            userConfigFetchInFlight = false;
            Msg.warn(this, "Failed to fetch user config: " + error.getMessage());
            return null;
        });
    }

    private CopilotConfig sanitizeCopilotConfig(CopilotConfig config) {
        if (config == null || options == null) {
            return config;
        }
        logCopilotConfigSummary(config);
        String backendApiKey = options.getApiKey();
        if (backendApiKey == null || backendApiKey.isBlank()) {
            return config;
        }
        Object rawKey = config.getAdditionalParams().get("api_key");
        if (rawKey instanceof String && backendApiKey.equals(rawKey)) {
            Map<String, Object> adjusted = new HashMap<>(config.getAdditionalParams());
            adjusted.remove("api_key");
            Msg.warn(this, "Copilot config API key matches backend key; removing to avoid invalid LLM auth.");
            return new CopilotConfig(
                config.getModelName(),
                config.getModelProvider(),
                adjusted
            );
        }
        return config;
    }

    private void logCopilotConfigSummary(CopilotConfig config) {
        if (config == null) {
            return;
        }
        Map<String, Object> params = config.getAdditionalParams();
        Set<String> keys = params != null ? params.keySet() : Collections.emptySet();
        Object apiKey = params != null ? params.get("api_key") : null;
        String apiKeySummary = apiKey instanceof String
            ? "api_key=present(len=" + ((String) apiKey).length() + ")"
            : "api_key=missing";
        Msg.info(this, "Copilot config received: provider="
            + config.getModelProvider()
            + ", model=" + config.getModelName()
            + ", params=" + keys
            + ", " + apiKeySummary);
    }
    
    /**
     * Clear the singleton instance. Should be called when services are disposed.
     */
    public static void clearInstance() {
        instance = null;
    }
    
    
    public Program getCurrentProgram() {
        return currentProgram;
    }
    
    /**
     * Get the singleton instance of ZenyardService.
     * @return The current instance, or null if not initialized
     */
    public static ZenyardService getInstance() {
        return instance;
    }
    
    /**
     * Get the current program from the singleton services instance.
     * This is a convenience static method that can be called from anywhere.
     * @return The current program, or null if no program is loaded or services not initialized
     */
    public static Program getProgram() {
        if (instance == null) {
            return null;
        }
        return instance.getCurrentProgram();
    }
    
    public ZenyardOptions getOptions() {
        return options;
    }
    
    public StatusBarManager getStatusBarManager() {
        return statusBarManager;
    }
    
    public CopilotProvider getCopilotProvider() {
        return copilotProvider;
    }
    
    public ApiClient getApiClient() {
        return apiClient;
    }
    
    public BinariesApi getBinariesApi() {
        return binariesApi;
    }
    
    public UserApi getUserApi() {
        return userApi;
    }

    public UsageState getUsageState() {
        return usageState;
    }

    public void setUsageState(UsageState usageState) {
        this.usageState = usageState != null ? usageState : UsageState.unknown();
        if (copilotProvider != null) {
            SwingUtilities.invokeLater(() -> copilotProvider.refreshState());
        }
    }

    public boolean isServerConnected() {
        return serverConnected;
    }

    private void setServerConnected(boolean connected) {
        boolean changed = this.serverConnected != connected;
        this.serverConnected = connected;
        if (changed && copilotProvider != null) {
            SwingUtilities.invokeLater(() -> copilotProvider.refreshState());
        }
        if (changed && connected) {
            // If Copilot started while the server was unreachable, the initial user-config fetch may
            // have failed and been skipped thereafter. Retry on reconnection (throttled).
            fetchUserConfigAsync(false);
        }
    }
    
    public TrackChangesTaskManager getTrackChangesTaskManager() {
        return trackChangesTaskManager;
    }

    /**
     * Set the TrackChangesTaskManager once it is created by the plugin.
     */
    public void setTrackChangesTaskManager(TrackChangesTaskManager manager) {
        this.trackChangesTaskManager = manager;
    }
    
    public EventDispatcher getEventDispatcher() {
        return eventDispatcher;
    }

    private StatusBarActions createStatusBarActions() {
        return new StatusBarActions() {
            @Override
            public void onRerun() {
                Program program = getCurrentProgram();
                if (program == null || program.isClosed()) {
                    Msg.warn(this, "Status bar rerun ignored: no active program");
                    return;
                }
                if (isUsageBlocked()) {
                    showUsageBlockedDialog();
                    return;
                }
                if (isBinaryPaused()) {
                    showBinaryPausedDialog();
                    return;
                }
                if (statusBarManager == null || eventDispatcher == null) {
                    Msg.warn(this, "Status bar rerun ignored: missing dependencies");
                    return;
                }
                QueueRevisionsTask queueRevisionsTask = new QueueRevisionsTask(
                    plugin.getTool(), program, statusBarManager, eventDispatcher, true);
                ZenyardGhidraPlugin.executeBackgroundTask(queueRevisionsTask);

                BinariesApi api = binariesApi;
                if (api == null) {
                    Msg.warn(this, "Status bar rerun ignored: binaries API unavailable");
                    return;
                }
                UploadRevisionsTask uploadRevisionsTask = new UploadRevisionsTask(
                    plugin.getTool(), api, statusBarManager, program, eventDispatcher);
                ZenyardGhidraPlugin.executeBackgroundTask(uploadRevisionsTask);

                ZenyardProgramProperties props = new ZenyardProgramProperties(program);
                props.setString("changes_detected", "false");

                StatusBarViewModel viewModel = statusBarManager.getViewModel();
                if (viewModel != null) {
                    StatusBarState current = viewModel.getStateSnapshot();
                    viewModel.updateState(current.withShowRerun(false));
                }
            }

            @Override
            public void onInitialUpload() {
                Program program = getCurrentProgram();
                if (program == null || program.isClosed()) {
                    Msg.warn(this, "Status bar initial upload ignored: no active program");
                    return;
                }
                if (isUsageBlocked()) {
                    showUsageBlockedDialog();
                    return;
                }
                if (isBinaryPaused()) {
                    showBinaryPausedDialog();
                    return;
                }
                if (statusBarManager == null || eventDispatcher == null) {
                    Msg.warn(this, "Status bar initial upload ignored: missing dependencies");
                    return;
                }

                InitialQuestionsDialog.InitialQuestionsResult result =
                    InitialQuestionsDialog.showDialog(plugin.getTool(), options, program, true);
                if (result == null || !result.isAccepted()) {
                    statusBarManager.refreshDisplayNow();
                    return;
                }

                ZenyardProgramProperties props = new ZenyardProgramProperties(program);
                props.setString("asked_initial_questions", "true");
                props.setString("allow_preprocessing", String.valueOf(result.isAllowPreprocessing()));
                if (result.getBinaryInstructions() != null) {
                    props.setString("binary_instructions", result.getBinaryInstructions());
                }
                props.setString("ready_for_analysis", "true");
                props.setString("initial_questions_deferred", "false");

                eventDispatcher.publish(new ZenyardEvent(
                    ZenyardEvent.EventType.INITIAL_DIALOG_CONFIRMED, "StatusBar"));

                statusBarManager.refreshDisplayNow();
            }

            @Override
            public void onReviewTerms() {
                if (options == null) {
                    Msg.warn(this, "Review Terms ignored: options unavailable");
                    return;
                }
                boolean accepted = OnboardingDialog.showDialog(plugin.getTool(), options);
                int acceptedVersion = accepted ? EulaDialog.EULA_VERSION : -1;
                try {
                    options.updateConfiguration(Map.of("accepted_eula_version", acceptedVersion));
                } catch (java.io.IOException e) {
                    Msg.showError(this, plugin.getTool().getActiveWindow(), "Configuration Error",
                        "Failed to update EULA acceptance in zenyard.json", e);
                }
                if (accepted) {
                    plugin.activateAfterEulaAcceptance();
                }
                if (statusBarManager != null) {
                    statusBarManager.refreshDisplayNow();
                }
            }

            @Override
            public void onUsageDetails() {
                UsageDetailsDialog.showDialog(plugin.getTool(), getUsageState());
            }
        };
    }

    private boolean isUsageBlocked() {
        UsageState state = usageState;
        return state != null && state.isBlocked();
    }

    private void showUsageBlockedDialog() {
        UsageState.showBlockedDialog(plugin.getTool().getActiveWindow(), usageState);
    }

    /**
     * Check if the current binary is paused (persisted flag set by PollServerStatusTask).
     */
    public boolean isBinaryPaused() {
        Program program = getCurrentProgram();
        if (program == null || program.isClosed()) {
            return false;
        }
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        return "true".equals(props.getString("binary_paused"));
    }

    private void showBinaryPausedDialog() {
        UsageState state = usageState;
        if (state != null && state.isBlocked()) {
            UsageState.showBlockedDialog(plugin.getTool().getActiveWindow(), state);
        } else {
            Msg.showError(this, plugin.getTool().getActiveWindow(),
                "Analysis Paused",
                "Analysis is currently paused for this binary.\n"
                    + "Check your usage quota or contact Zenyard support.");
        }
    }
    
    public AnalysisProgressMonitor getAnalysisProgressMonitor() {
        return analysisProgressMonitor;
    }

    public QueuePositionMonitor getQueuePositionMonitor() {
        return queuePositionMonitor;
    }
    
    /**
     * Queue a foreground task to be executed by StartForegroundTasksTask.
     * Notifies waiting tasks that the queue has been updated.
     */
    public void queueForegroundTask(ForegroundTask task) {
        queueLock.lock();
        try {
            foregroundTaskQueue.offer(task);
            synchronized (queueNotification) {
                queueNotification.notifyAll();
            }
        } finally {
            queueLock.unlock();
        }
    }
    
    /**
     * Get and remove the next foreground task from the queue.
     * @return The next task, or null if queue is empty
     */
    public ForegroundTask pollForegroundTask() {
        queueLock.lock();
        try {
            return foregroundTaskQueue.poll();
        } finally {
            queueLock.unlock();
        }
    }
    
    /**
     * Check if foreground task queue is empty.
     */
    public boolean isForegroundTaskQueueEmpty() {
        queueLock.lock();
        try {
            return foregroundTaskQueue.isEmpty();
        } finally {
            queueLock.unlock();
        }
    }
    
    /**
     * Wait for foreground task queue to become non-empty.
     * This method blocks until a task is added to the queue.
     */
    public void waitForForegroundTask() throws InterruptedException {
        synchronized (queueNotification) {
            while (isForegroundTaskQueueEmpty()) {
                queueNotification.wait();
            }
        }
    }

    /**
     * Wake foreground queue waiters (used when shutting down waiting tasks).
     */
    public void notifyForegroundTaskWaiters() {
        synchronized (queueNotification) {
            queueNotification.notifyAll();
        }
    }
    
    /**
     * Check if a foreground task is currently active.
     */
    public boolean isForegroundTaskActive() {
        return foregroundTaskActive;
    }
    
    /**
     * Set whether a foreground task is currently active.
     */
    public void setForegroundTaskActive(boolean active) {
        this.foregroundTaskActive = active;
    }
}
