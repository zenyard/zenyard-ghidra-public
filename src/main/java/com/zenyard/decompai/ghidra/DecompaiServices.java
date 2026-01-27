package com.zenyard.decompai.ghidra;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import com.zenyard.decompai.ghidra.api.DecompaiApiClientFactory;
import com.zenyard.decompai.ghidra.api.generated.ApiClient;
import com.zenyard.decompai.ghidra.api.generated.ApiException;
import com.zenyard.decompai.ghidra.api.generated.api.BinariesApi;
import com.zenyard.decompai.ghidra.api.generated.api.UserApi;
import com.zenyard.decompai.ghidra.copilot.CopilotConfigMapper;
import com.zenyard.decompai.ghidra.config.DecompaiOptions;
import com.zenyard.decompai.ghidra.copilot.CopilotController;
import com.zenyard.decompai.ghidra.copilot.CopilotProvider;
import com.zenyard.decompai.ghidra.copilot.CopilotViewModel;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.illum.IlluminatorController;
import com.zenyard.decompai.ghidra.initialization.InitialQuestionsDialog;
import com.zenyard.decompai.ghidra.status.AnalysisProgressMonitor;
import com.zenyard.decompai.ghidra.status.StatusBarActions;
import com.zenyard.decompai.ghidra.status.StatusBarManager;
import com.zenyard.decompai.ghidra.status.StatusBarState;
import com.zenyard.decompai.ghidra.status.StatusBarViewModel;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;
import com.zenyard.decompai.ghidra.tracking.TrackChangesTaskManager;
import com.zenyard.decompai.ghidra.tasks.ForegroundTask;
import com.zenyard.decompai.ghidra.upload.QueueRevisionsTask;
import com.zenyard.decompai.ghidra.upload.UploadRevisionsTask;
import com.zenyard.decompai.ghidra.util.LoggerUtil;
import com.zenyard.decompai.ghidra.events.EventDispatcher;

import java.util.ArrayDeque;
import java.util.Deque;
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
public class DecompaiServices {
    
    private static DecompaiServices instance;
    
    private final DecompaiGhidraPlugin plugin;
    private final DecompaiOptions options;
    private Program currentProgram;
    
    private ApiClient apiClient;
    private BinariesApi binariesApi;
    private UserApi userApi;
    private IlluminatorController illuminatorController;
    private CopilotProvider copilotProvider;
    private CopilotController copilotController;
    private CopilotViewModel copilotViewModel;
    private StatusBarManager statusBarManager;
    private TrackChangesTaskManager trackChangesTaskManager;
    private EventDispatcher eventDispatcher;
    private AnalysisProgressMonitor analysisProgressMonitor;
    private volatile boolean userConfigFetchStarted;
    
    // Foreground task queue infrastructure
    private final Deque<ForegroundTask> foregroundTaskQueue = new ArrayDeque<>();
    private final ReentrantLock queueLock = new ReentrantLock();
    private volatile boolean foregroundTaskActive = false;
    private final Object queueNotification = new Object();
    
    public DecompaiServices(DecompaiGhidraPlugin plugin, DecompaiOptions options) {
        this.plugin = plugin;
        this.options = options;
        this.currentProgram = null;
        
        // Set singleton instance
        instance = this;
        
        // Initialize API client if configured
        if (options.isConfigured()) {
            this.apiClient = DecompaiApiClientFactory.createApiClient(options);
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
            fetchUserConfigAsync();
        }
        plugin.getTool().addComponentProvider(copilotProvider, false);
        
        // Illuminator will be initialized when program is activated
    }

    public void onProgramActivated(Program program) {
        this.currentProgram = program;
        
        // Configure logging for this program
        LoggerUtil.configureForProgram(program.getName(), options.getLogLevel());
        
        // Initialize API client if not already initialized
        if (apiClient == null && options.isConfigured()) {
            apiClient = DecompaiApiClientFactory.createApiClient(options);
            binariesApi = new BinariesApi(apiClient);
            userApi = new UserApi(apiClient);
            fetchUserConfigAsync();
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

    private void fetchUserConfigAsync() {
        if (userApi == null || copilotController == null || userConfigFetchStarted) {
            return;
        }
        userConfigFetchStarted = true;
        CompletableFuture.supplyAsync(() -> {
            try {
                return userApi.getUserConfig();
            } catch (ApiException e) {
                throw new RuntimeException(e);
            }
        }).thenAccept(userConfig -> {
            if (userConfig == null) {
                return;
            }
            com.zenyard.decompai.ghidra.copilot.CopilotConfig config =
                CopilotConfigMapper.fromUserConfig(userConfig);
            if (config != null && copilotController != null) {
                copilotController.setCopilotConfig(sanitizeCopilotConfig(config));
            }
        }).exceptionally(error -> {
            Msg.warn(this, "Failed to fetch user config: " + error.getMessage());
            return null;
        });
    }

    private com.zenyard.decompai.ghidra.copilot.CopilotConfig sanitizeCopilotConfig(
            com.zenyard.decompai.ghidra.copilot.CopilotConfig config) {
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
            java.util.Map<String, Object> adjusted = new java.util.HashMap<>(config.getAdditionalParams());
            adjusted.remove("api_key");
            Msg.warn(this, "Copilot config API key matches backend key; removing to avoid invalid LLM auth.");
            return new com.zenyard.decompai.ghidra.copilot.CopilotConfig(
                config.getModelName(),
                config.getModelProvider(),
                adjusted
            );
        }
        return config;
    }

    private void logCopilotConfigSummary(com.zenyard.decompai.ghidra.copilot.CopilotConfig config) {
        if (config == null) {
            return;
        }
        java.util.Map<String, Object> params = config.getAdditionalParams();
        java.util.Set<String> keys = params != null ? params.keySet() : java.util.Collections.emptySet();
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
    
    public void analyzeCurrentFunction() {
        if (currentProgram == null) {
            Msg.showWarn(this, plugin.getTool().getActiveWindow(), 
                "No Program", "No program is currently loaded.");
            return;
        }
        
        if (!options.isConfigured()) {
            Msg.showWarn(this, plugin.getTool().getActiveWindow(),
                "Not Configured", "DecompAI is not configured. Please set your API key in the configuration dialog.");
            return;
        }
        
        if (illuminatorController == null) {
            Msg.showWarn(this, plugin.getTool().getActiveWindow(),
                "Not Initialized", "Illuminator not initialized.");
            return;
        }
        
        // Get current address from tool's location
        // For now, we'll need to get it from the context or current location
        // This is a simplified version - in a full implementation, we'd get it from ActionContext
        Address currentAddress = currentProgram.getMinAddress(); // Placeholder
        
        // TODO: Get actual current address from tool's location provider
        // For now, analyze the first function as a placeholder
        illuminatorController.analyzeFunctionAt(currentProgram, currentAddress);
    }
    
    public Program getCurrentProgram() {
        return currentProgram;
    }
    
    /**
     * Get the singleton instance of DecompaiServices.
     * @return The current instance, or null if not initialized
     */
    public static DecompaiServices getInstance() {
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
    
    public DecompaiOptions getOptions() {
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
                if (statusBarManager == null || eventDispatcher == null) {
                    Msg.warn(this, "Status bar rerun ignored: missing dependencies");
                    return;
                }
                QueueRevisionsTask queueRevisionsTask = new QueueRevisionsTask(
                    plugin.getTool(), program, statusBarManager, eventDispatcher, true);
                DecompaiGhidraPlugin.executeBackgroundTask(queueRevisionsTask);

                BinariesApi api = binariesApi;
                if (api == null) {
                    Msg.warn(this, "Status bar rerun ignored: binaries API unavailable");
                    return;
                }
                UploadRevisionsTask uploadRevisionsTask = new UploadRevisionsTask(
                    plugin.getTool(), api, statusBarManager, program, eventDispatcher);
                DecompaiGhidraPlugin.executeBackgroundTask(uploadRevisionsTask);

                DecompaiProgramProperties props = new DecompaiProgramProperties(program);
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

                DecompaiProgramProperties props = new DecompaiProgramProperties(program);
                props.setString("asked_initial_questions", "true");
                props.setString("auto_apply_results", String.valueOf(result.isAutoApplyResults()));
                props.setString("allow_preprocessing", String.valueOf(result.isAllowPreprocessing()));
                if (result.getBinaryInstructions() != null) {
                    props.setString("binary_instructions", result.getBinaryInstructions());
                }
                props.setString("ready_for_analysis", "true");
                props.setString("initial_questions_deferred", "false");

                eventDispatcher.publish(new DecompaiEvent(
                    DecompaiEvent.EventType.INITIAL_DIALOG_CONFIRMED, "StatusBar"));

                statusBarManager.refreshDisplayNow();
            }
        };
    }
    
    public AnalysisProgressMonitor getAnalysisProgressMonitor() {
        return analysisProgressMonitor;
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

