package com.zenyard.ghidra.upload;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import com.zenyard.ghidra.api.generated.ApiException;
import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.model.BinaryDetails;
import com.zenyard.ghidra.api.generated.model.OriginalLanguages;
import com.zenyard.ghidra.api.generated.model.PostBinaryBody;
import com.zenyard.ghidra.api.generated.model.PostBinaryResponse;
import com.zenyard.ghidra.config.ZenyardOptions;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.tasks.StatusBarAwareTask;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.status.StatusBarManager;
import com.zenyard.ghidra.status.StatusBarPriorities;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import com.zenyard.ghidra.ZenyardService;
import com.zenyard.ghidra.usage.UsageState;

/**
 * Background task to register a binary with the API.
 * Waits for ANALYSIS_COMPLETE and INITIAL_DIALOG_CONFIRMED events.
 * Publishes BINARY_REGISTERED and BINARY_ID_AVAILABLE events on completion.
 * 
 * NOTE: mirrors zenyard_ida/register_binary_task.py
 */
public class RegisterBinaryTask extends StatusBarAwareTask {
    
    private static final String TASK_ID = "register_binary";
    private static final int STATUS_BAR_PRIORITY = StatusBarPriorities.REGISTER_BINARY;
    
    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final ZenyardOptions options;
    private final String binaryInstructions;
    private final Program program;
    private UUID binaryId;
    
    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean analysisComplete = false;
    private volatile boolean initialDialogConfirmed = false;
    private volatile boolean shouldStop = false;
    
    public RegisterBinaryTask(PluginTool tool, BinariesApi binariesApi,
                             ZenyardOptions options, String binaryInstructions, StatusBarManager statusBarManager,
                             Program program) {
        this(tool, binariesApi, options, binaryInstructions, statusBarManager, program, null);
    }
    
    public RegisterBinaryTask(PluginTool tool, BinariesApi binariesApi,
                             ZenyardOptions options, String binaryInstructions, StatusBarManager statusBarManager,
                             Program program, ZenyardService services) {
        super("Register Binary with Zenyard", true, false, false,
            services != null ? services.getEventDispatcher() : null, statusBarManager, TASK_ID, STATUS_BAR_PRIORITY);
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.options = options;
        this.binaryInstructions = binaryInstructions;
        this.program = program;
    }
    
    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        Set<ZenyardEvent.EventType> types = new HashSet<>();
        types.add(ZenyardEvent.EventType.ANALYSIS_COMPLETE);
        types.add(ZenyardEvent.EventType.INITIAL_DIALOG_CONFIRMED);
        types.add(ZenyardEvent.EventType.PROGRAM_DEACTIVATED);
        return types;
    }
    
    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.ANALYSIS_COMPLETE) {
            synchronized (waitLock) {
                analysisComplete = true;
                waitLock.notify();
            }
        } else if (event.getType() == ZenyardEvent.EventType.INITIAL_DIALOG_CONFIRMED) {
            synchronized (waitLock) {
                initialDialogConfirmed = true;
                waitLock.notify();
            }
        } else if (event.getType() == ZenyardEvent.EventType.PROGRAM_DEACTIVATED) {
            synchronized (waitLock) {
                shouldStop = true;
                waitLock.notify(); // Wake up any waiting threads
            }
        }
    }
    
    @Override
    protected void doRun(TaskMonitor monitor) {
        try {
            if (isUsageBlocked()) {
                return;
            }
            // Check if already registered (initial state check)
            ZenyardProgramProperties props = new ZenyardProgramProperties(program);
            String existingBinaryId = props.getString("binary_id");
            if (existingBinaryId != null && !existingBinaryId.isEmpty()) {
                // Already registered - publish BINARY_ID_AVAILABLE event
                try {
                    UUID existingId = UUID.fromString(existingBinaryId);
                    Map<String, Object> payload = new HashMap<>();
                    payload.put("binaryId", existingId);
                    publishEvent(new ZenyardEvent(ZenyardEvent.EventType.BINARY_ID_AVAILABLE, getTaskTitle(), payload));
                } catch (IllegalArgumentException e) {
                    // Invalid UUID, continue with registration
                }
                return;
            }
            
            // Check if prerequisites are already met
            String alreadyCompleted = props.getString("initial_analysis_complete");
            if ("true".equals(alreadyCompleted)) {
                analysisComplete = true;
            }
            
            String alreadyAsked = props.getString("asked_initial_questions");
            String alreadyUploaded = props.getString("initial_upload_complete");
            if ("true".equals(alreadyAsked) || "true".equals(alreadyUploaded)) {
                initialDialogConfirmed = true;
            }
            
            // Wait for prerequisites using events
            synchronized (waitLock) {
                while ((!analysisComplete || !initialDialogConfirmed) && !monitor.isCancelled() && !shouldStop) {
                    // Re-check properties periodically
                    alreadyCompleted = props.getString("initial_analysis_complete");
                    if ("true".equals(alreadyCompleted)) {
                        analysisComplete = true;
                    }
                    
                    alreadyAsked = props.getString("asked_initial_questions");
                    alreadyUploaded = props.getString("initial_upload_complete");
                    if ("true".equals(alreadyAsked) || "true".equals(alreadyUploaded)) {
                        initialDialogConfirmed = true;
                    }
                    
                    if (analysisComplete && initialDialogConfirmed) {
                        break;
                    }
                    
                    try {
                        waitLock.wait(1000); // Wait up to 1 second, then check again
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
            
            if (monitor.isCancelled() || shouldStop) {
                return;
            }

            if (isUsageBlocked()) {
                return;
            }

            runWithStatusBar(() -> {
                StatusBarManager statusBarManager = getStatusBarManager();

                // Get binary instructions from properties (set by ShowInitialQuestionsTask)
                String binaryInstructionsFromProps = props.getString("binary_instructions");
                String instructionsToUse = (binaryInstructionsFromProps != null && !binaryInstructionsFromProps.isEmpty()) 
                    ? binaryInstructionsFromProps : binaryInstructions;

                if (statusBarManager != null) {
                    statusBarManager.updateTaskStatus(TASK_ID, "Registering binary...", null, true);
                }

                // Get binary path name
                String binaryName = program.getName();
                if (binaryName == null || binaryName.isEmpty()) {
                    binaryName = "unknown";
                }

                // Extract platform and OS version (simplified - can be enhanced)
                String platform = extractPlatform();
                String osVersion = extractOsVersion();

                // Check for Swift
                boolean hasSwift = checkForSwift();

                // Create binary details
                OriginalLanguages originalLanguages = new OriginalLanguages();
                originalLanguages.setSwift(hasSwift);

                BinaryDetails details = new BinaryDetails();
                if (instructionsToUse != null && !instructionsToUse.isEmpty()) {
                    details.setInstructions(instructionsToUse);
                }
                details.setOriginalLanguages(originalLanguages);
                if (platform != null) {
                    details.setPlatform(BinaryDetails.PlatformEnum.fromValue(platform));
                }
                if (osVersion != null && !osVersion.isEmpty()) {
                    details.setOsVersion(osVersion);
                }

                // Create binary
                PostBinaryBody body = new PostBinaryBody();
                body.setName(binaryName);
                body.setDetails(details);

                PostBinaryResponse response = CompletableFuture.supplyAsync(() -> {
                    try {
                        return binariesApi.createBinary(body);
                    } catch (ApiException e) {
                        throw new RuntimeException(e);
                    }
                }).get();
                this.binaryId = response.getBinaryId();

                // Store binary ID
                props.setString("binary_id", binaryId.toString());

                // Publish events
                Map<String, Object> payload = new HashMap<>();
                payload.put("binaryId", binaryId);
                publishEvent(new ZenyardEvent(ZenyardEvent.EventType.BINARY_REGISTERED, getTaskTitle(), payload));
                publishEvent(new ZenyardEvent(ZenyardEvent.EventType.BINARY_ID_AVAILABLE, getTaskTitle(), payload));
            });
            
        } catch (Exception e) {
            // Extract root cause for better error messages
            Throwable rootCause = e;
            while (rootCause.getCause() != null && rootCause.getCause() != rootCause) {
                rootCause = rootCause.getCause();
            }
            
            String errorMessage = "Failed to register binary with Zenyard server.\n\n";
            
            // Check if it's a redirect error (307/308)
            String errorMsg = e.getMessage();
            if (errorMsg != null && (errorMsg.contains("status 307") 
                || errorMsg.contains("status 308") 
                || errorMsg.contains("Redirect error"))) {
                errorMessage += "Redirect Error: The server is redirecting the request.\n\n";
                errorMessage += "This usually means:\n";
                errorMessage += "1. Server URL might need a trailing slash or different path\n";
                errorMessage += "2. Server URL might need to use HTTPS instead of HTTP (or vice versa)\n";
                errorMessage += "3. Server is redirecting to a different endpoint\n\n";
                errorMessage += "Current server URL: " + options.getServerUrl() + "\n\n";
                errorMessage += "Please check the server URL in Tools → Zenyard → Configuration...";
            } else if (rootCause instanceof java.net.ConnectException 
                || rootCause instanceof java.net.UnknownHostException 
                || (e.getMessage() != null && e.getMessage().contains("ConnectException"))) {
                errorMessage += "Connection Error: Unable to connect to the Zenyard server.\n\n";
                errorMessage += "Please check:\n";
                errorMessage += "1. Server URL is correct: " + options.getServerUrl() + "\n";
                errorMessage += "2. Server is running and accessible\n";
                errorMessage += "3. Network connectivity is working\n";
                errorMessage += "4. Firewall/proxy settings allow the connection\n\n";
                errorMessage += "You can verify the connection in Tools → Zenyard → Configuration...";
            } else if (rootCause instanceof ApiException) {
                ApiException apiEx = (ApiException) rootCause;
                if (apiEx.getCode() == 401) {
                    errorMessage += "Authentication Error: Invalid API key.\n\n";
                    errorMessage += "Please check your API key in Tools → Zenyard → Configuration...";
                } else {
                    errorMessage += "API Error: " + rootCause.getMessage();
                }
            } else {
                errorMessage += "Error: " + e.getMessage();
            }
            
            java.awt.Component parent = getActiveWindowSafely();
            Msg.showError(this, parent, "Registration Error", errorMessage, e);
            throw new RuntimeException("Failed to register binary", e);
        }
    }

    private boolean isUsageBlocked() {
        ZenyardService services = ZenyardService.getInstance();
        if (services == null) {
            return false;
        }
        UsageState usageState = services.getUsageState();
        if (usageState != null && usageState.isBlocked()) {
            UsageState.showBlockedDialog(tool.getActiveWindow(), usageState);
            return true;
        }
        return false;
    }
    
    /**
     * Extract platform from program (simplified).
     */
    private String extractPlatform() {
        // TODO: Implement platform extraction (iOS/macOS detection)
        // For now, return null
        return null;
    }
    
    /**
     * Extract OS version from program (simplified).
     */
    private String extractOsVersion() {
        return null;
    }
    
    /**
     * Check if program has Swift code.
     */
    private boolean checkForSwift() {
        return false;
    }
    
    
    public UUID getBinaryId() {
        return binaryId;
    }

    private java.awt.Component getActiveWindowSafely() {
        if (tool == null) {
            return null;
        }
        try {
            return tool.getActiveWindow();
        } catch (RuntimeException ex) {
            Msg.debug(this, "Failed to resolve active window: " + ex.getMessage());
            return null;
        }
    }
}
