package com.zenyard.decompai.ghidra.illum;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import ghidra.util.task.TaskMonitor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

import com.zenyard.decompai.ghidra.api.generated.api.BinariesApi;
import com.zenyard.decompai.ghidra.api.generated.model.AddObjectsToCurrentRevisionParams;
import com.zenyard.decompai.ghidra.api.generated.model.CreateRevisionParams;
import com.zenyard.decompai.ghidra.api.generated.model.FinishAndAnalyzeCurrentRevisionParams;
import com.zenyard.decompai.ghidra.api.generated.model.Function;
import com.zenyard.decompai.ghidra.api.generated.model.GetInferencesResponse;
import com.zenyard.decompai.ghidra.api.generated.model.Inference;
import com.zenyard.decompai.ghidra.api.generated.model.MaybeUnknownInference;
import com.zenyard.decompai.ghidra.api.generated.model.ModelObject;
import com.zenyard.decompai.ghidra.api.generated.model.Range;
import com.zenyard.decompai.ghidra.config.DecompaiOptions;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;
import com.zenyard.decompai.ghidra.storage.InferenceStorage;
import com.zenyard.decompai.ghidra.upload.RegisterBinaryTask;
import com.zenyard.decompai.ghidra.util.BinarySerializer;
import com.zenyard.decompai.ghidra.util.FunctionSerializer;

/**
 * Triggers remote static-analysis tools via API and applies results as annotations.
 * 
 * Serializes function/binary data (mirroring decompai_ida/binary.py logic).
 * 
 * NOTE: mirrors functionality in decompai_ida for executing static analysis tools.
 * All program modifications use Ghidra's transaction system.
 * 
 * Uses the same revision-based API workflow as IlluminatorController.analyzeFunction().
 */
public class StaticToolsExecutor {
    
    private static final int MAX_RETRIES_FOR_REVISION_REQUEST = 5;
    private static final int MAX_INFERENCES_PER_REQUEST = 50;
    private static final int POLL_INTERVAL_MS = 1000; // 1 second
    private static final int MAX_POLL_ATTEMPTS = 300; // 5 minutes max
    private static final int MAX_OBJECTS_PER_REVISION = 64;
    private static final int MAX_UPLOAD_BYTES = 2 * 1024 * 1024; // 2MB
    
    /**
     * Result of tool execution.
     */
    public static class ToolResult {
        private final boolean success;
        private final String toolName;
        private final Object results; // Will be typed based on tool
        
        public ToolResult(boolean success, String toolName, Object results) {
            this.success = success;
            this.toolName = toolName;
            this.results = results;
        }
        
        public boolean isSuccess() {
            return success;
        }
        
        public String getToolName() {
            return toolName;
        }
        
        public Object getResults() {
            return results;
        }
    }
    
    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final DecompaiOptions options;
    private final FunctionHighlighter functionHighlighter;
    private final VariableHighlighter variableHighlighter;
    private final FunctionOverviewAnnotator overviewAnnotator;
    
    public StaticToolsExecutor(PluginTool tool, BinariesApi binariesApi, DecompaiOptions options) {
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.options = options;
        this.functionHighlighter = new FunctionHighlighter();
        this.variableHighlighter = new VariableHighlighter();
        this.overviewAnnotator = new FunctionOverviewAnnotator();
    }
    
    /**
     * Execute a static analysis tool for the entire program.
     * Uses revision-based workflow: serialize binary, upload original file, create revision with all functions,
     * finish & analyze, poll inferences, apply results.
     */
    public CompletableFuture<ToolResult> executeTool(Program program, String toolName, TaskMonitor monitor) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                monitor.setMessage("Executing " + toolName + " on program...");
                monitor.setProgress(5);
                monitor.checkCanceled();
                
                // Step 1: Get or register binary ID
                UUID binaryId = getOrRegisterBinary(program, monitor);
                if (binaryId == null) {
                    throw new RuntimeException("Failed to get or register binary");
                }
                
                monitor.setMessage("Serializing binary...");
                monitor.setProgress(10);
                monitor.checkCanceled();
                
                // Step 2: Serialize binary and upload original file
                BinarySerializer.SerializedBinary serializedBinary = BinarySerializer.serializeBinary(program);
                retryApiCall(() -> {
                    CompletableFuture.supplyAsync(() -> {
                        try {
                            // Convert byte array to File for upload
                            java.io.File tempFile = java.io.File.createTempFile("binary_upload_", ".bin");
                            java.nio.file.Files.write(tempFile.toPath(), serializedBinary.getData());
                            try {
                                binariesApi.putOriginalFile(serializedBinary.getName(), binaryId, tempFile, serializedBinary.getType());
                            } finally {
                                tempFile.delete();
                            }
                            return null;
                        } catch (java.io.IOException | com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                            throw new RuntimeException(e);
                        }
                    }).get();
                    return null;
                }, "Upload original file", monitor);
                
                monitor.setMessage("Serializing functions...");
                monitor.setProgress(20);
                monitor.checkCanceled();
                
                // Step 3: Serialize all functions
                FunctionManager functionManager = program.getFunctionManager();
                java.util.Iterator<ghidra.program.model.listing.Function> functionsIter = functionManager.getFunctions(true);
                List<Function> apiFunctions = new ArrayList<>();
                
                while (functionsIter.hasNext()) {
                    ghidra.program.model.listing.Function function = functionsIter.next();
                    monitor.checkCanceled();
                    Function apiFunction = FunctionSerializer.serializeFunction(program, function, 0);
                    if (validateFunction(apiFunction)) {
                        apiFunctions.add(apiFunction);
                    }
                }
                
                if (apiFunctions.isEmpty()) {
                    Msg.showWarn(this, tool.getActiveWindow(), "No Valid Functions",
                        "No valid functions found to analyze");
                    return new ToolResult(false, toolName, "No valid functions");
                }
                
                monitor.setMessage("Creating revision...");
                monitor.setProgress(30);
                monitor.checkCanceled();
                
                // Step 4: Get revision number and create revision
                DecompaiProgramProperties props = new DecompaiProgramProperties(program);
                int currentRevision = getCurrentRevision(props);
                int nextRevision = currentRevision + 1;
                
                retryApiCall(() -> {
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
                }, "Create revision " + nextRevision, monitor);
                
                monitor.setMessage("Adding objects to revision...");
                monitor.setProgress(40);
                monitor.checkCanceled();
                
                // Step 5: Add objects in chunks (max 64 per revision, max 2MB per upload)
                List<ModelObject> objectsToUpload = new ArrayList<>();
                for (Function func : apiFunctions) {
                    ModelObject obj = new ModelObject();
                    obj.setActualInstance(func);
                    objectsToUpload.add(obj);
                }
                int totalSize = 0;
                List<ModelObject> currentChunk = new ArrayList<>();
                
                for (ModelObject obj : objectsToUpload) {
                    monitor.checkCanceled();
                    // Estimate size (rough approximation)
                    int objSize = estimateObjectSize(obj);
                    if (currentChunk.size() >= MAX_OBJECTS_PER_REVISION || 
                        (totalSize + objSize > MAX_UPLOAD_BYTES && !currentChunk.isEmpty())) {
                        // Upload current chunk
                        AddObjectsToCurrentRevisionParams addParams = new AddObjectsToCurrentRevisionParams();
                        addParams.setObjects(currentChunk);
                        retryApiCall(() -> {
                            CompletableFuture.supplyAsync(() -> {
                                try {
                                    binariesApi.addObjectsToCurrentRevision(binaryId, addParams);
                                    return null;
                                } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                                    throw new RuntimeException(e);
                                }
                            }).get();
                            return null;
                        }, "Add objects to revision " + nextRevision, monitor);
                        currentChunk.clear();
                        totalSize = 0;
                    }
                    currentChunk.add(obj);
                    totalSize += objSize;
                }
                
                // Upload remaining chunk
                if (!currentChunk.isEmpty()) {
                    AddObjectsToCurrentRevisionParams addParams = new AddObjectsToCurrentRevisionParams();
                    addParams.setObjects(currentChunk);
                    retryApiCall(() -> {
                        CompletableFuture.supplyAsync(() -> {
                            try {
                                binariesApi.addObjectsToCurrentRevision(binaryId, addParams);
                                return null;
                            } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                                throw new RuntimeException(e);
                            }
                        }).get();
                        return null;
                    }, "Add objects to revision " + nextRevision, monitor);
                }
                
                monitor.setMessage("Finishing and analyzing revision...");
                monitor.setProgress(60);
                monitor.checkCanceled();
                
                // Step 6: Finish and analyze revision
                FinishAndAnalyzeCurrentRevisionParams finishParams = new FinishAndAnalyzeCurrentRevisionParams();
                finishParams.setAnalyzeDependents(true); // analyzeDependents=true for program-level
                
                retryApiCall(() -> {
                    CompletableFuture.supplyAsync(() -> {
                        try {
                            binariesApi.finishAndAnalyzeCurrentRevision(binaryId, finishParams);
                            return null;
                        } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                            throw new RuntimeException(e);
                        }
                    }).get();
                    return null;
                }, "Finish revision " + nextRevision, monitor);
                
                // Step 7: Update revision number atomically
                props.setInt("revision", nextRevision);
                
                monitor.setMessage("Polling for inferences...");
                monitor.setProgress(70);
                monitor.checkCanceled();
                
                // Step 8: Poll for inferences
                List<MaybeUnknownInference> inferences = pollForInferences(monitor, binaryId, nextRevision);
                
                monitor.setMessage("Applying inferences...");
                monitor.setProgress(90);
                monitor.checkCanceled();
                
                // Step 9: Apply inferences
                if (!inferences.isEmpty()) {
                    // Convert MaybeUnknownInference to Inference
                    List<Inference> convertedInferences = inferences.stream()
                        .map(MaybeUnknownInference::getInference)
                        .filter(inference -> inference != null)
                        .collect(java.util.stream.Collectors.toList());
                    InferenceStorage inferenceStorage = new InferenceStorage(program);
                    InferenceApplier inferenceApplier = new InferenceApplier(overviewAnnotator, inferenceStorage);
                    inferenceApplier.applyInferences(program, convertedInferences);
                }
                
                monitor.setProgress(100);
                monitor.setMessage("Tool execution complete");
                
                return new ToolResult(true, toolName, inferences);
            } catch (CancelledException e) {
                return new ToolResult(false, toolName, "Cancelled");
            } catch (Exception e) {
                Msg.showError(this, tool.getActiveWindow(), "Tool Execution Error",
                    "Failed to execute tool " + toolName + ": " + e.getMessage(), e);
                return new ToolResult(false, toolName, null);
            }
        });
    }
    
    /**
     * Execute a static analysis tool for a specific function.
     * Uses revision-based workflow matching IlluminatorController.analyzeFunction() pattern.
     */
    public CompletableFuture<ToolResult> executeToolForFunction(Program program, ghidra.program.model.listing.Function function, 
            String toolName, TaskMonitor monitor) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                monitor.setMessage("Executing " + toolName + " on function " + function.getName() + "...");
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
                Function apiFunction = FunctionSerializer.serializeFunction(program, function, 0);
                
                // Validate function (drop if invalid)
                if (!validateFunction(apiFunction)) {
                    Msg.showWarn(this, tool.getActiveWindow(), "Invalid Function",
                        "Function at " + function.getEntryPoint() + " is invalid and will be skipped");
                    return new ToolResult(false, toolName, "Invalid function");
                }
                
                monitor.setMessage("Creating revision " + nextRevision + "...");
                monitor.setProgress(20);
                monitor.checkCanceled();
                
                // Step 4: Create revision
                retryApiCall(() -> {
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
                }, "Create revision " + nextRevision, monitor);
                
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
                
                retryApiCall(() -> {
                    CompletableFuture.supplyAsync(() -> {
                        try {
                            binariesApi.addObjectsToCurrentRevision(binaryId, addParams);
                            return null;
                        } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                            throw new RuntimeException(e);
                        }
                    }).get();
                    return null;
                }, "Add function to revision " + nextRevision, monitor);
                
                monitor.setMessage("Finishing and analyzing revision...");
                monitor.setProgress(40);
                monitor.checkCanceled();
                
                // Step 6: Finish and analyze revision
                FinishAndAnalyzeCurrentRevisionParams finishParams = new FinishAndAnalyzeCurrentRevisionParams();
                finishParams.setAnalyzeDependents(false); // analyzeDependents=false for single function
                
                retryApiCall(() -> {
                    CompletableFuture.supplyAsync(() -> {
                        try {
                            binariesApi.finishAndAnalyzeCurrentRevision(binaryId, finishParams);
                            return null;
                        } catch (com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                            throw new RuntimeException(e);
                        }
                    }).get();
                    return null;
                }, "Finish revision " + nextRevision, monitor);
                
                // Step 7: Update revision number atomically
                props.setInt("revision", nextRevision);
                
                monitor.setMessage("Polling for inferences...");
                monitor.setProgress(50);
                monitor.checkCanceled();
                
                // Step 8: Poll for inferences
                List<MaybeUnknownInference> inferences = pollForInferences(monitor, binaryId, nextRevision);
                
                monitor.setMessage("Applying inferences...");
                monitor.setProgress(90);
                monitor.checkCanceled();
                
                // Step 9: Apply inferences
                if (!inferences.isEmpty()) {
                    // Convert MaybeUnknownInference to Inference
                    List<Inference> convertedInferences = inferences.stream()
                        .map(MaybeUnknownInference::getInference)
                        .filter(inference -> inference != null)
                        .collect(java.util.stream.Collectors.toList());
                    InferenceStorage inferenceStorage = new InferenceStorage(program);
                    InferenceApplier inferenceApplier = new InferenceApplier(overviewAnnotator, inferenceStorage);
                    inferenceApplier.applyInferences(program, convertedInferences);
                }
                
                monitor.setProgress(100);
                monitor.setMessage("Tool execution complete");
                
                return new ToolResult(true, toolName, inferences);
            } catch (CancelledException e) {
                return new ToolResult(false, toolName, "Cancelled");
            } catch (Exception e) {
                Msg.showError(this, tool.getActiveWindow(), "Tool Execution Error",
                    "Failed to execute tool " + toolName + ": " + e.getMessage(), e);
                return new ToolResult(false, toolName, null);
            }
        });
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
        // Get StatusBarManager if available (may be null in this context)
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
    private boolean validateFunction(Function func) {
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
    private <T> T retryApiCall(java.util.concurrent.Callable<T> request, String description, TaskMonitor monitor) {
        int retries = 0;
        while (retries < MAX_RETRIES_FOR_REVISION_REQUEST) {
            try {
                monitor.checkCanceled();
                return request.call();
            } catch (CancelledException e) {
                // Wrap CancelledException in RuntimeException since we're in a lambda
                throw new RuntimeException("Operation cancelled", e);
            } catch (Exception e) {
                retries++;
                if (retries >= MAX_RETRIES_FOR_REVISION_REQUEST) {
                    throw new RuntimeException("Failed " + description + " after " + MAX_RETRIES_FOR_REVISION_REQUEST + " retries", e);
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
                monitor.checkCanceled();
                
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
                
            } catch (CancelledException e) {
                break;
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
     * Estimate object size for chunking.
     * Rough approximation based on code length.
     */
    private int estimateObjectSize(ModelObject obj) {
        Object actual = obj.getActualInstance();
        if (actual instanceof Function) {
            Function func = (Function) actual;
            String code = func.getCode();
            if (code != null) {
                return code.length() * 2; // Rough estimate: 2 bytes per character
            }
        }
        return 1024; // Default estimate
    }
}

