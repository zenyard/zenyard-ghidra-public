package com.zenyard.decompai.ghidra.illum;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

import com.zenyard.decompai.ghidra.api.generated.api.BinariesApi;
import com.zenyard.decompai.ghidra.api.generated.model.AddObjectsToCurrentRevisionParams;
import com.zenyard.decompai.ghidra.api.generated.model.CreateRevisionParams;
import com.zenyard.decompai.ghidra.api.generated.model.FinishAndAnalyzeCurrentRevisionParams;
import com.zenyard.decompai.ghidra.api.generated.model.GetInferencesResponse;
import com.zenyard.decompai.ghidra.api.generated.model.Inference;
import com.zenyard.decompai.ghidra.api.generated.model.MaybeUnknownInference;
import com.zenyard.decompai.ghidra.api.generated.model.ModelObject;
import com.zenyard.decompai.ghidra.api.generated.model.Range;
import com.zenyard.decompai.ghidra.config.DecompaiOptions;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;
import com.zenyard.decompai.ghidra.storage.InferenceStorage;
import com.zenyard.decompai.ghidra.upload.RegisterBinaryTask;
import com.zenyard.decompai.ghidra.util.FunctionSerializer;

/**
 * Orchestrates static analysis requests and applies results (colors, names, comments).
 * 
 * NOTE: mirrors logic in decompai_ida/apply_inferences_task.py and related modules.
 */
public class IlluminatorController {
    
    private static final int MAX_RETRIES_FOR_REVISION_REQUEST = 5;
    private static final int MAX_INFERENCES_PER_REQUEST = 50;
    private static final int POLL_INTERVAL_MS = 1000; // 1 second
    private static final int MAX_POLL_ATTEMPTS = 300; // 5 minutes max
    
    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final FunctionOverviewAnnotator overviewAnnotator;
    private final DecompaiOptions options;
    
    public IlluminatorController(PluginTool tool, BinariesApi binariesApi, DecompaiOptions options) {
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.options = options;
        this.overviewAnnotator = new FunctionOverviewAnnotator();
    }
    
    /**
     * Analyze a function and apply results.
     * All program modifications are wrapped in transactions.
     * 
     * Follows the revision-based API workflow matching IDA's UploadRevisionsTask pattern.
     */
    public void analyzeFunction(Program program, ghidra.program.model.listing.Function function) {
        Task task = new Task("Analyzing Function with DecompAI", true, false, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    monitor.setMessage("Getting or registering binary...");
                    monitor.setProgress(5);
                    monitor.checkCanceled();
                    
                    // Step 1: Get or register binary ID
                    UUID binaryId = getOrRegisterBinary(program, monitor);
                    if (binaryId == null) {
                        throw new RuntimeException("Failed to get or register binary");
                    }
                    
                    monitor.setMessage("Getting revision number...");
                    monitor.setProgress(10);
                    monitor.checkCanceled();
                    
                    // Step 2: Get current revision number
                    DecompaiProgramProperties props = new DecompaiProgramProperties(program);
                    int currentRevision = getCurrentRevision(props);
                    int nextRevision = currentRevision + 1;
                    
                    monitor.setMessage("Serializing function data...");
                    monitor.setProgress(15);
                    monitor.checkCanceled();
                    
                    // Step 3: Serialize function data
                    com.zenyard.decompai.ghidra.api.generated.model.Function apiFunction = 
                        FunctionSerializer.serializeFunction(program, function, 0);
                    
                    // Validate function (drop if invalid)
                    if (!validateFunction(apiFunction)) {
                        Msg.showWarn(this, tool.getActiveWindow(), "Invalid Function",
                            "Function at " + function.getEntryPoint() + " is invalid and will be skipped");
                        return;
                    }
                    
                    monitor.setMessage("Creating revision " + nextRevision + "...");
                    monitor.setProgress(20);
                    monitor.checkCanceled();
                    
                    // Step 4: Create revision
                    retryApiRequest(() -> {
                        CreateRevisionParams createParams = new CreateRevisionParams();
                        createParams.setNumber(nextRevision);
                        CompletableFuture.supplyAsync(() -> {
                            try {
                                binariesApi.createRevision(binaryId, createParams);
                                return null;
                            } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                                throw new RuntimeException(e);
                            }
                        }).get();
                        return null;
                    }, "Create revision " + nextRevision, MAX_RETRIES_FOR_REVISION_REQUEST);
                    
                    monitor.setMessage("Adding function to revision...");
                    monitor.setProgress(30);
                    monitor.checkCanceled();
                    
                    // Step 5: Add function to revision
                    List<ModelObject> objects = new ArrayList<>();
                    ModelObject obj = new ModelObject();
                    obj.setActualInstance(apiFunction);
                    objects.add(obj);
                    AddObjectsToCurrentRevisionParams addParams = new AddObjectsToCurrentRevisionParams();
                    addParams.setObjects(objects);
                    
                    retryApiRequest(() -> {
                        CompletableFuture.supplyAsync(() -> {
                            try {
                                binariesApi.addObjectsToCurrentRevision(binaryId, addParams);
                                return null;
                            } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                                throw new RuntimeException(e);
                            }
                        }).get();
                        return null;
                    }, "Add function to revision " + nextRevision, MAX_RETRIES_FOR_REVISION_REQUEST);
                    
                    monitor.setMessage("Finishing and analyzing revision...");
                    monitor.setProgress(40);
                    monitor.checkCanceled();
                    
                    // Step 6: Finish and analyze revision
                    FinishAndAnalyzeCurrentRevisionParams finishParams = new FinishAndAnalyzeCurrentRevisionParams();
                    finishParams.setAnalyzeDependents(false); // analyzeDependents=false for single function
                    
                    retryApiRequest(() -> {
                        CompletableFuture.supplyAsync(() -> {
                            try {
                                binariesApi.finishAndAnalyzeCurrentRevision(binaryId, finishParams);
                                return null;
                            } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                                throw new RuntimeException(e);
                            }
                        }).get();
                        return null;
                    }, "Finish revision " + nextRevision, MAX_RETRIES_FOR_REVISION_REQUEST);
                    
                    // Step 7: Update revision number atomically
                    props.setInt("revision", nextRevision);
                    
                    monitor.setMessage("Polling for inferences...");
                    monitor.setProgress(50);
                    monitor.checkCanceled();
                    
                    // Step 8: Poll for inferences
                    List<MaybeUnknownInference> inferences = pollForInferences(monitor, binaryId, nextRevision);
                    // Convert MaybeUnknownInference to Inference for applier
                    List<Inference> convertedInferences = inferences.stream()
                        .map(MaybeUnknownInference::getInference)
                        .filter(inference -> inference != null)
                            .collect(java.util.stream.Collectors.toList());
                    
                    monitor.setMessage("Applying inferences...");
                    monitor.setProgress(90);
                    monitor.checkCanceled();
                    
                    // Step 9: Apply inferences
                    if (!convertedInferences.isEmpty()) {
                        InferenceStorage inferenceStorage = new InferenceStorage(program);
                        InferenceApplier inferenceApplier = new InferenceApplier(overviewAnnotator, inferenceStorage);
                        inferenceApplier.applyInferences(program, convertedInferences);
                    }
                    
                    monitor.setProgress(100);
                    monitor.setMessage("Analysis complete");
                    
                    Msg.info(this, "DecompAI: Successfully analyzed function " + function.getName() + 
                        " at " + function.getEntryPoint() + " (revision " + nextRevision + ")");
                } catch (CancelledException e) {
                    // User cancelled
                } catch (Exception e) {
                    Msg.showError(this, tool.getActiveWindow(), "Analysis Error",
                        "Failed to analyze function: " + e.getMessage(), e);
                    throw new RuntimeException("Failed to analyze function", e);
                }
            }
        };
        
        tool.execute(task);
    }
    
    /**
     * Get or register binary ID.
     */
    private UUID getOrRegisterBinary(Program program, TaskMonitor monitor) {
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        String existingBinaryId = props.getString("binary_id");
        if (existingBinaryId != null && !existingBinaryId.isEmpty()) {
            try {
                return UUID.fromString(existingBinaryId);
            } catch (IllegalArgumentException e) {
                // Invalid UUID, continue to register
            }
        }
        
        // Register binary inline - create BinariesApi for registration
        com.zenyard.decompai.ghidra.api.generated.ApiClient apiClient = 
            com.zenyard.decompai.ghidra.api.DecompaiApiClientFactory.createApiClient(options);
        BinariesApi tempBinariesApi = new BinariesApi(apiClient);
        // StatusBarManager not available in this context, pass null
        com.zenyard.decompai.ghidra.status.StatusBarManager statusBarManager = null;
        RegisterBinaryTask registerTask = new RegisterBinaryTask(tool, tempBinariesApi, options, "", statusBarManager, program);
        tool.execute(registerTask);
        // Wait for task to complete
        // Note: tool.execute() for background tasks is non-blocking, so we need to poll for binary_id
        String binaryIdStr = null;
        for (int i = 0; i < 600; i++) {
            DecompaiProgramProperties currentProps = new DecompaiProgramProperties(program);
            binaryIdStr = currentProps.getString("binary_id");
            if (binaryIdStr != null && !binaryIdStr.isEmpty()) {
                break;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Binary registration interrupted", e);
            }
        }
        if (binaryIdStr == null || binaryIdStr.isEmpty()) {
            throw new RuntimeException("Binary registration failed or not yet complete after 60 seconds");
        }
        return java.util.UUID.fromString(binaryIdStr);
    }
    
    /**
     * Get current revision number.
     */
    private int getCurrentRevision(DecompaiProgramProperties props) {
        // Use getInt() since revision is stored as an integer
        Integer revision = props.getInt("revision");
        if (revision != null) {
            return revision;
        }
        // Start at revision 1 (or use high starting number like IDA's 10_000)
        return 1;
    }
    
    /**
     * Validate function object before uploading.
     * Matches IDA's validate_object() logic.
     */
    private boolean validateFunction(com.zenyard.decompai.ghidra.api.generated.model.Function func) {
        try {
            // Basic validation - check that function has code
            if (func.getCode() == null || func.getCode().isEmpty()) {
                return false;
            }
            
            // Validate ranges if present
            if (func.getRanges() != null) {
                String code = func.getCode();
                for (Range range : func.getRanges()) {
                    if (range.getStart() < 0 || range.getStart() + range.getLength() > code.length()) {
                        return false; // Range out of code bounds
                    }
                }
            }
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Retry API request with exponential backoff.
     * Matches IDA's _retry_api_request_forever pattern.
     */
    private <T> T retryApiRequest(java.util.concurrent.Callable<T> request, String description, int maxRetries) {
        int retries = 0;
        while (retries < maxRetries) {
            try {
                return request.call();
            } catch (Exception e) {
                retries++;
                if (retries >= maxRetries) {
                    throw new RuntimeException("Failed " + description + " after " + maxRetries + " retries", e);
                }
                // Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms
                long delayMs = 100L * (1L << (retries - 1));
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Interrupted during retry", ie);
                }
            }
        }
        throw new RuntimeException("Failed " + description);
    }
    
    /**
     * Poll for inferences until all are received.
     * Matches IDA's DownloadInferencesTask._fetch_inferences() pattern.
     */
    private List<MaybeUnknownInference> pollForInferences(TaskMonitor monitor, UUID binaryId, int revisionNumber) {
        List<MaybeUnknownInference> allInferences = new ArrayList<>();
        Integer cursor = null; // Start with null cursor
        int pollAttempts = 0;
        
        while (pollAttempts < MAX_POLL_ATTEMPTS && !monitor.isCancelled()) {
            try {
                // Fetch inferences
                GetInferencesResponse response = binariesApi.getInferences(
                    revisionNumber, binaryId, cursor, MAX_INFERENCES_PER_REQUEST);
                
                if (response.getInferences() != null) {
                    allInferences.addAll(response.getInferences());
                }
                
                // Check if there are more inferences
                if (!response.getHasNext()) {
                    // Done fetching for this revision
                    break;
                }
                
                // Update cursor for next page
                cursor = response.getCursor();
                
                // Continue immediately to fetch next page
                pollAttempts++;
                
            } catch (Exception e) {
                // Wait before retrying
                try {
                    Thread.sleep(POLL_INTERVAL_MS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
                pollAttempts++;
            }
        }
        
        return allInferences;
    }
    
    /**
     * Analyze the function at the given address.
     */
    public void analyzeFunctionAt(Program program, Address address) {
        Function function = program.getFunctionManager().getFunctionAt(address);
        if (function == null) {
            Msg.showWarn(this, tool.getActiveWindow(), "No Function",
                "No function found at address " + address);
            return;
        }
        
        analyzeFunction(program, function);
    }
}

