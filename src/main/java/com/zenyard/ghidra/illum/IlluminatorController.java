package com.zenyard.ghidra.illum;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.model.Inference;
import com.zenyard.ghidra.api.generated.model.MaybeUnknownInference;
import com.zenyard.ghidra.api.generated.model.ModelObject;
import com.zenyard.ghidra.config.ZenyardOptions;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.storage.InferenceStorage;
import com.zenyard.ghidra.util.FunctionSerializer;

/**
 * Orchestrates static analysis requests and applies results (colors, names, comments).
 * 
 * NOTE: mirrors logic in zenyard_ida/apply_inferences_task.py and related modules.
 */
public class IlluminatorController {
    
    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final FunctionOverviewAnnotator overviewAnnotator;
    private final RevisionWorkflowManager workflowManager;
    
    public IlluminatorController(PluginTool tool, BinariesApi binariesApi, ZenyardOptions options) {
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.overviewAnnotator = new FunctionOverviewAnnotator();
        this.workflowManager = new RevisionWorkflowManager(tool, binariesApi, options);
    }
    
    /**
     * Analyze a function and apply results.
     * All program modifications are wrapped in transactions.
     * 
     * Follows the revision-based API workflow matching IDA's UploadRevisionsTask pattern.
     */
    public void analyzeFunction(Program program, Function function) {
        Task task = new Task("Analyzing Function with Zenyard", true, false, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    monitor.setMessage("Getting or registering binary...");
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
                    com.zenyard.ghidra.api.generated.model.Function apiFunction = 
                        FunctionSerializer.serializeFunction(program, function, 0);
                    
                    // Validate function (drop if invalid)
                    if (!workflowManager.validateFunction(apiFunction)) {
                        Msg.showWarn(this, tool.getActiveWindow(), "Invalid Function",
                            "Function at " + function.getEntryPoint() + " is invalid and will be skipped");
                        return;
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
                    // Convert MaybeUnknownInference to Inference for applier
                    List<Inference> convertedInferences = inferences.stream()
                        .map(MaybeUnknownInference::getInference)
                        .filter(inference -> inference != null)
                        .collect(Collectors.toList());
                    
                    monitor.setMessage("Applying inferences...");
                    monitor.setProgress(90);
                    monitor.checkCanceled();
                    
                    // Step 9: Apply inferences
                    if (!convertedInferences.isEmpty()) {
                        InferenceStorage inferenceStorage = new InferenceStorage(program);
                        InferenceApplier inferenceApplier = new InferenceApplier(overviewAnnotator, inferenceStorage, tool);
                        inferenceApplier.applyInferences(program, convertedInferences);
                    }
                    
                    monitor.setProgress(100);
                    monitor.setMessage("Analysis complete");
                    
                    Msg.info(this, "Zenyard: Successfully analyzed function " + function.getName() 
                        + " at " + function.getEntryPoint() + " (revision " + nextRevision + ")");
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

