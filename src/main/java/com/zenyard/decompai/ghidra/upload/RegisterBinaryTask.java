package com.zenyard.decompai.ghidra.upload;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import com.zenyard.decompai.ghidra.api.generated.ApiException;
import com.zenyard.decompai.ghidra.api.generated.api.BinariesApi;
import com.zenyard.decompai.ghidra.api.generated.model.BinaryDetails;
import com.zenyard.decompai.ghidra.api.generated.model.OriginalLanguages;
import com.zenyard.decompai.ghidra.api.generated.model.PostBinaryBody;
import com.zenyard.decompai.ghidra.api.generated.model.PostBinaryResponse;
import com.zenyard.decompai.ghidra.config.DecompaiOptions;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.tasks.StatusBarAwareTask;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;
import com.zenyard.decompai.ghidra.status.StatusBarManager;
import com.zenyard.decompai.ghidra.status.StatusBarPriorities;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import com.zenyard.decompai.ghidra.ZenyardService;

/**
 * Background task to register a binary with the API.
 * Waits for ANALYSIS_COMPLETE and INITIAL_DIALOG_CONFIRMED events.
 * Publishes BINARY_REGISTERED and BINARY_ID_AVAILABLE events on completion.
 * 
 * NOTE: mirrors decompai_ida/register_binary_task.py
 */
public class RegisterBinaryTask extends StatusBarAwareTask {
    
    private static final String TASK_ID = "register_binary";
    private static final int STATUS_BAR_PRIORITY = StatusBarPriorities.REGISTER_BINARY;
    
    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final DecompaiOptions options;
    private final String binaryInstructions;
    private final Program program;
    private UUID binaryId;
    
    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean analysisComplete = false;
    private volatile boolean initialDialogConfirmed = false;
    private volatile boolean shouldStop = false;
    
    public RegisterBinaryTask(PluginTool tool, BinariesApi binariesApi,
                             DecompaiOptions options, String binaryInstructions, StatusBarManager statusBarManager,
                             Program program) {
        this(tool, binariesApi, options, binaryInstructions, statusBarManager, program, null);
    }
    
    public RegisterBinaryTask(PluginTool tool, BinariesApi binariesApi,
                             DecompaiOptions options, String binaryInstructions, StatusBarManager statusBarManager,
                             Program program, ZenyardService services) {
        super("Register Binary with DecompAI", true, false, false,
            services != null ? services.getEventDispatcher() : null, statusBarManager, TASK_ID, STATUS_BAR_PRIORITY);
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.options = options;
        this.binaryInstructions = binaryInstructions;
        this.program = program;
    }
    
    @Override
    public Set<DecompaiEvent.EventType> getSubscribedEventTypes() {
        Set<DecompaiEvent.EventType> types = new HashSet<>();
        types.add(DecompaiEvent.EventType.ANALYSIS_COMPLETE);
        types.add(DecompaiEvent.EventType.INITIAL_DIALOG_CONFIRMED);
        types.add(DecompaiEvent.EventType.PROGRAM_DEACTIVATED);
        return types;
    }
    
    @Override
    public void handleEvent(DecompaiEvent event) {
        if (event.getType() == DecompaiEvent.EventType.ANALYSIS_COMPLETE) {
            synchronized (waitLock) {
                analysisComplete = true;
                waitLock.notify();
            }
        } else if (event.getType() == DecompaiEvent.EventType.INITIAL_DIALOG_CONFIRMED) {
            synchronized (waitLock) {
                initialDialogConfirmed = true;
                waitLock.notify();
            }
        } else if (event.getType() == DecompaiEvent.EventType.PROGRAM_DEACTIVATED) {
            synchronized (waitLock) {
                shouldStop = true;
                waitLock.notify(); // Wake up any waiting threads
            }
        }
    }
    
    @Override
    protected void doRun(TaskMonitor monitor) {
        try {
            // Check if already registered (initial state check)
            DecompaiProgramProperties props = new DecompaiProgramProperties(program);
            String existingBinaryId = props.getString("binary_id");
            if (existingBinaryId != null && !existingBinaryId.isEmpty()) {
                // Already registered - publish BINARY_ID_AVAILABLE event
                try {
                    UUID existingId = UUID.fromString(existingBinaryId);
                    Map<String, Object> payload = new HashMap<>();
                    payload.put("binaryId", existingId);
                    publishEvent(new DecompaiEvent(DecompaiEvent.EventType.BINARY_ID_AVAILABLE, getTaskTitle(), payload));
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
                publishEvent(new DecompaiEvent(DecompaiEvent.EventType.BINARY_REGISTERED, getTaskTitle(), payload));
                publishEvent(new DecompaiEvent(DecompaiEvent.EventType.BINARY_ID_AVAILABLE, getTaskTitle(), payload));
            });
            
        } catch (Exception e) {
            // Extract root cause for better error messages
            Throwable rootCause = e;
            while (rootCause.getCause() != null && rootCause.getCause() != rootCause) {
                rootCause = rootCause.getCause();
            }
            
            String errorMessage = "Failed to register binary with DecompAI server.\n\n";
            
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
                errorMessage += "Please check the server URL in Tools → DecompAI → Configuration...";
            } else if (rootCause instanceof java.net.ConnectException 
                || rootCause instanceof java.net.UnknownHostException 
                || (e.getMessage() != null && e.getMessage().contains("ConnectException"))) {
                errorMessage += "Connection Error: Unable to connect to the DecompAI server.\n\n";
                errorMessage += "Please check:\n";
                errorMessage += "1. Server URL is correct: " + options.getServerUrl() + "\n";
                errorMessage += "2. Server is running and accessible\n";
                errorMessage += "3. Network connectivity is working\n";
                errorMessage += "4. Firewall/proxy settings allow the connection\n\n";
                errorMessage += "You can verify the connection in Tools → DecompAI → Configuration...";
            } else if (rootCause instanceof ApiException) {
                ApiException apiEx = (ApiException) rootCause;
                if (apiEx.getCode() == 401) {
                    errorMessage += "Authentication Error: Invalid API key.\n\n";
                    errorMessage += "Please check your API key in Tools → DecompAI → Configuration...";
                } else {
                    errorMessage += "API Error: " + rootCause.getMessage();
                }
            } else {
                errorMessage += "Error: " + e.getMessage();
            }
            
            Msg.showError(this, tool.getActiveWindow(), "Registration Error", errorMessage, e);
            throw new RuntimeException("Failed to register binary", e);
        }
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
}
