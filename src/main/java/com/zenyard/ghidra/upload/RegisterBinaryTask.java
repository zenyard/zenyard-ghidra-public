package com.zenyard.ghidra.upload;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import com.zenyard.ghidra.api.generated.ApiException;
import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.api.UserApi;
import com.zenyard.ghidra.api.generated.model.BinaryDetails;
import com.zenyard.ghidra.api.generated.model.Decompiler;
import com.zenyard.ghidra.api.generated.model.DecompilerType;
import com.zenyard.ghidra.api.generated.model.OriginalLanguages;
import com.zenyard.ghidra.api.generated.model.PostBinaryBody;
import com.zenyard.ghidra.api.generated.model.PostBinaryResponse;
import com.zenyard.ghidra.config.ZenyardOptions;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.tasks.StatusBarAwareTask;
import com.zenyard.ghidra.ui.BinarySizeLimitDialog;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.status.StatusBarManager;
import com.zenyard.ghidra.status.StatusBarPriorities;
import com.zenyard.ghidra.util.BinarySizeLimitGate;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
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

            if (isBinarySizeBlocked()) {
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

                String inputFileSha256 = program.getExecutableSHA256();
                if (inputFileSha256 != null && !inputFileSha256.isEmpty()) {
                    details.setInputFileSha256(inputFileSha256);
                }

                String ghidraVersion;
                try {
                    ghidraVersion = Application.getApplicationVersion();
                } catch (Exception e) {
                    ghidraVersion = null;
                }
                Decompiler decompiler = new Decompiler();
                decompiler.setType(DecompilerType.GHIDRA);
                if (ghidraVersion != null) {
                    decompiler.setVersion(ghidraVersion);
                }
                details.setDecompiler(decompiler);

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
        ZenyardService services = ZenyardService.getInstanceForTool(tool);
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

    private static final int SIZE_GATE_INITIAL_BACKOFF_MS = 5_000;
    private static final int SIZE_GATE_MAX_BACKOFF_MS = 30_000;
    private static final int SIZE_GATE_MAX_RETRIES = 60;

    private boolean isBinarySizeBlocked() {
        ZenyardService services = ZenyardService.getInstanceForTool(tool);
        UserApi userApi = services != null ? services.getUserApi() : null;

        int backoffMs = SIZE_GATE_INITIAL_BACKOFF_MS;

        for (int attempt = 0; attempt <= SIZE_GATE_MAX_RETRIES; attempt++) {
            BinarySizeLimitGate.CheckResult result = BinarySizeLimitGate.check(program, userApi);

            if (result.isPassed()) {
                BinarySizeLimitGate.persistResult(program, result);
                return false;
            }

            if (result.isBlocked()) {
                BinarySizeLimitGate.persistResult(program, result);
                StatusBarManager statusBarManager = getStatusBarManager();
                if (statusBarManager != null) {
                    statusBarManager.refreshDisplayNow();
                }
                if (result.getMaxBinarySizeMb() != null) {
                    BinarySizeLimitDialog.showDialogIfNeeded(tool, program, result.getMaxBinarySizeMb());
                }
                Msg.warn(this, "Binary size gate did not pass: " + result.getMessage());
                return true;
            }

            if (shouldStop || program.isClosed()) {
                return true;
            }

            if (attempt < SIZE_GATE_MAX_RETRIES) {
                Msg.info(this, "Binary size gate not verified (attempt " + (attempt + 1)
                    + "), retrying in " + backoffMs + "ms: " + result.getMessage());
                try {
                    Thread.sleep(backoffMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return true;
                }
                backoffMs = Math.min(backoffMs * 2, SIZE_GATE_MAX_BACKOFF_MS);
            }
        }

        Msg.warn(this, "Binary size gate could not be verified after retries, proceeding optimistically");
        return false;
    }
    
    // Mach-O constants
    private static final int LC_BUILD_VERSION = 0x32;
    private static final int MACHO_MAGIC_LE = 0xFEEDFACF;  // 64-bit little-endian
    private static final int MACHO_MAGIC_BE = 0xCFFAEDFE;  // 64-bit big-endian
    private static final Map<Integer, String> MACHO_PLATFORM_MAP = new HashMap<>();
    static {
        MACHO_PLATFORM_MAP.put(1, "macos");
        MACHO_PLATFORM_MAP.put(2, "ios");
        MACHO_PLATFORM_MAP.put(3, "tvos");
        MACHO_PLATFORM_MAP.put(4, "watchos");
        MACHO_PLATFORM_MAP.put(6, "ios");   // iOS simulator
        MACHO_PLATFORM_MAP.put(7, "tvos");  // tvOS simulator
        MACHO_PLATFORM_MAP.put(8, "watchos"); // watchOS simulator
    }

    /**
     * Returns a two-element array [platform, osVersion] parsed from the Mach-O
     * LC_BUILD_VERSION load command embedded in the program's memory, or
     * [null, null] if the data cannot be found or parsed.
     */
    private String[] extractMachoPlatformAndOsVersion() {
        try {
            if (!MachoLoader.MACH_O_NAME.equals(program.getExecutableFormat())) {
                return new String[]{null, null};
            }

            Memory memory = program.getMemory();
            Address imageBase = program.getImageBase();

            // Read Mach-O magic to determine endianness
            int magic = memory.getInt(imageBase);
            boolean littleEndian = (magic == MACHO_MAGIC_LE);
            if (magic != MACHO_MAGIC_LE && magic != MACHO_MAGIC_BE) {
                return new String[]{null, null};
            }

            // Mach-O 64-bit header: magic(4) cputype(4) cpusubtype(4) filetype(4)
            //                        ncmds(4) sizeofcmds(4) flags(4) reserved(4)
            int ncmds = readInt(memory, imageBase.add(16), littleEndian);
            long cmdOffset = 32; // header size for 64-bit Mach-O

            for (int i = 0; i < ncmds; i++) {
                Address cmdAddr = imageBase.add(cmdOffset);
                int cmd = readInt(memory, cmdAddr, littleEndian);
                int cmdsize = readInt(memory, cmdAddr.add(4), littleEndian);

                if (cmd == LC_BUILD_VERSION) {
                    // LC_BUILD_VERSION layout:
                    //   cmd(4) cmdsize(4) platform(4) minos(4) sdk(4) ntools(4)
                    int platformVal = readInt(memory, cmdAddr.add(8), littleEndian);
                    int minosPacked = readInt(memory, cmdAddr.add(12), littleEndian);

                    String platform = MACHO_PLATFORM_MAP.get(platformVal);
                    String osVersion = unpackMachoVersion(minosPacked);
                    return new String[]{platform, osVersion};
                }

                if (cmdsize <= 0) break;
                cmdOffset += cmdsize;
            }
        } catch (Exception e) {
            Msg.debug(this, "Could not extract Mach-O platform/os_version: " + e.getMessage());
        }
        return new String[]{null, null};
    }

    private int readInt(Memory memory, Address addr, boolean littleEndian) throws MemoryAccessException {
        byte[] bytes = new byte[4];
        memory.getBytes(addr, bytes);
        if (littleEndian) {
            return ((bytes[3] & 0xFF) << 24) | ((bytes[2] & 0xFF) << 16)
                 | ((bytes[1] & 0xFF) << 8)  |  (bytes[0] & 0xFF);
        } else {
            return ((bytes[0] & 0xFF) << 24) | ((bytes[1] & 0xFF) << 16)
                 | ((bytes[2] & 0xFF) << 8)  |  (bytes[3] & 0xFF);
        }
    }

    private String unpackMachoVersion(int packed) {
        int major = (packed >> 16) & 0xFFFF;
        int minor = (packed >> 8) & 0xFF;
        int patch = packed & 0xFF;
        return major + "." + minor + "." + patch;
    }

    /**
     * Extract platform from program's Mach-O LC_BUILD_VERSION load command.
     */
    private String extractPlatform() {
        return extractMachoPlatformAndOsVersion()[0];
    }

    /**
     * Extract SDK/OS version from program's Mach-O LC_BUILD_VERSION load command.
     */
    private String extractOsVersion() {
        return extractMachoPlatformAndOsVersion()[1];
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
