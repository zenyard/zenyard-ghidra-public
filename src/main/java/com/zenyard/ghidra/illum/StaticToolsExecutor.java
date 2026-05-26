package com.zenyard.ghidra.illum;

import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.util.task.TaskMonitor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.model.Function;
import com.zenyard.ghidra.api.generated.model.Inference;
import com.zenyard.ghidra.api.generated.model.MaybeUnknownInference;
import com.zenyard.ghidra.api.generated.model.ModelObject;
import com.zenyard.ghidra.config.ZenyardOptions;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.storage.InferenceStorage;
import com.zenyard.ghidra.util.BinarySerializer;
import com.zenyard.ghidra.util.FunctionSerializer;

/**
 * Triggers remote static-analysis tools via API and applies results as annotations.
 * 
 * Serializes function/binary data (mirroring zenyard_ida/binary.py logic).
 * 
 * NOTE: mirrors functionality in zenyard_ida for executing static analysis tools.
 * All program modifications use Ghidra's transaction system.
 * 
 * Uses the same revision-based API workflow as IlluminatorController.analyzeFunction().
 */
public class StaticToolsExecutor {
    
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
    private final FunctionOverviewAnnotator overviewAnnotator;
    private final RevisionWorkflowManager workflowManager;
    
    public StaticToolsExecutor(PluginTool tool, BinariesApi binariesApi, ZenyardOptions options) {
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.overviewAnnotator = new FunctionOverviewAnnotator();
        this.workflowManager = new RevisionWorkflowManager(tool, binariesApi, options);
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
                UUID binaryId = workflowManager.getOrRegisterBinary(program, monitor);
                if (binaryId == null) {
                    throw new RuntimeException("Failed to get or register binary");
                }
                
                monitor.setMessage("Serializing binary...");
                monitor.setProgress(10);
                monitor.checkCanceled();
                
                // Step 2: Serialize binary and upload original file
                BinarySerializer.SerializedBinary serializedBinary = BinarySerializer.serializeBinary(program);
                workflowManager.executeApiRequest(() -> {
                    String encodedData = Base64.getEncoder().encodeToString(serializedBinary.getData());
                    binariesApi.putOriginalFile(serializedBinary.getName(), binaryId, encodedData, serializedBinary.getType());
                });
                
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
                    if (workflowManager.validateFunction(apiFunction)) {
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
                ZenyardProgramProperties props = new ZenyardProgramProperties(program);
                int currentRevision = workflowManager.getCurrentRevision(props);
                int nextRevision = currentRevision + 1;
                
                workflowManager.createRevision(binaryId, nextRevision);
                
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
                    if (currentChunk.size() >= MAX_OBJECTS_PER_REVISION 
                        || (totalSize + objSize > MAX_UPLOAD_BYTES && !currentChunk.isEmpty())) {
                        // Upload current chunk
                        workflowManager.addObjectsToRevision(binaryId, currentChunk);
                        currentChunk.clear();
                        totalSize = 0;
                    }
                    currentChunk.add(obj);
                    totalSize += objSize;
                }
                
                // Upload remaining chunk
                if (!currentChunk.isEmpty()) {
                    workflowManager.addObjectsToRevision(binaryId, currentChunk);
                }
                
                monitor.setMessage("Finishing and analyzing revision...");
                monitor.setProgress(60);
                monitor.checkCanceled();
                
                // Step 6: Finish and analyze revision
                workflowManager.finishAndAnalyzeRevision(binaryId, true);
                
                // Step 7: Update revision number atomically
                props.setInt("revision", nextRevision);
                
                monitor.setMessage("Polling for inferences...");
                monitor.setProgress(70);
                monitor.checkCanceled();
                
                // Step 8: Poll for inferences
                List<MaybeUnknownInference> inferences = workflowManager.pollForInferences(monitor, binaryId, nextRevision);
                
                monitor.setMessage("Applying inferences...");
                monitor.setProgress(90);
                monitor.checkCanceled();
                
                // Step 9: Apply inferences
                if (!inferences.isEmpty()) {
                    // Convert MaybeUnknownInference to Inference
                    List<Inference> convertedInferences = inferences.stream()
                        .map(MaybeUnknownInference::getInference)
                        .filter(inference -> inference != null)
                        .collect(Collectors.toList());
                    InferenceStorage inferenceStorage = new InferenceStorage(program);
                    InferenceApplier inferenceApplier = new InferenceApplier(overviewAnnotator, inferenceStorage, tool);
                    inferenceApplier.applyInferences(program, convertedInferences, monitor);
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
                UUID binaryId = workflowManager.getOrRegisterBinary(program, monitor);
                if (binaryId == null) {
                    throw new RuntimeException("Failed to get or register binary");
                }
                
                monitor.setMessage("Getting revision number...");
                monitor.setProgress(10);
                monitor.checkCanceled();
                
                // Step 2: Get current revision number
                ZenyardProgramProperties props = new ZenyardProgramProperties(program);
                int currentRevision = workflowManager.getCurrentRevision(props);
                int nextRevision = currentRevision + 1;
                
                monitor.setMessage("Serializing function data...");
                monitor.setProgress(15);
                monitor.checkCanceled();
                
                // Step 3: Serialize function data
                Function apiFunction = FunctionSerializer.serializeFunction(program, function, 0);
                
                // Validate function (drop if invalid)
                if (!workflowManager.validateFunction(apiFunction)) {
                    Msg.showWarn(this, tool.getActiveWindow(), "Invalid Function",
                        "Function at " + function.getEntryPoint() + " is invalid and will be skipped");
                    return new ToolResult(false, toolName, "Invalid function");
                }
                
                monitor.setMessage("Creating revision " + nextRevision + "...");
                monitor.setProgress(20);
                monitor.checkCanceled();
                
                // Step 4: Create revision
                workflowManager.createRevision(binaryId, nextRevision);
                
                monitor.setMessage("Adding function to revision...");
                monitor.setProgress(30);
                monitor.checkCanceled();
                
                // Step 5: Add function to revision
                List<ModelObject> objects = new ArrayList<>();
                ModelObject obj = new ModelObject();
                obj.setActualInstance(apiFunction);
                objects.add(obj);
                workflowManager.addObjectsToRevision(binaryId, objects);
                
                monitor.setMessage("Finishing and analyzing revision...");
                monitor.setProgress(40);
                monitor.checkCanceled();
                
                // Step 6: Finish and analyze revision
                workflowManager.finishAndAnalyzeRevision(binaryId, false);
                
                // Step 7: Update revision number atomically
                props.setInt("revision", nextRevision);
                
                monitor.setMessage("Polling for inferences...");
                monitor.setProgress(50);
                monitor.checkCanceled();
                
                // Step 8: Poll for inferences
                List<MaybeUnknownInference> inferences = workflowManager.pollForInferences(monitor, binaryId, nextRevision);
                
                monitor.setMessage("Applying inferences...");
                monitor.setProgress(90);
                monitor.checkCanceled();
                
                // Step 9: Apply inferences
                if (!inferences.isEmpty()) {
                    // Convert MaybeUnknownInference to Inference
                    List<Inference> convertedInferences = inferences.stream()
                        .map(MaybeUnknownInference::getInference)
                        .filter(inference -> inference != null)
                        .collect(Collectors.toList());
                    InferenceStorage inferenceStorage = new InferenceStorage(program);
                    InferenceApplier inferenceApplier = new InferenceApplier(overviewAnnotator, inferenceStorage, tool);
                    inferenceApplier.applyInferences(program, convertedInferences, monitor);
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

