package com.zenyard.ghidra.illum;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;

import com.zenyard.ghidra.api.ZenyardApiClientFactory;
import com.zenyard.ghidra.api.generated.ApiClient;
import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.model.AddObjectsToCurrentRevisionParams;
import com.zenyard.ghidra.api.generated.model.CreateRevisionParams;
import com.zenyard.ghidra.api.generated.model.FinishAndAnalyzeCurrentRevisionBody;
import com.zenyard.ghidra.api.generated.model.GetInferencesResponse;
import com.zenyard.ghidra.api.generated.model.MaybeUnknownInference;
import com.zenyard.ghidra.api.generated.model.ModelObject;
import com.zenyard.ghidra.api.generated.model.Range;
import com.zenyard.ghidra.config.ZenyardOptions;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.upload.RegisterBinaryTask;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Shared workflow manager for revision operations.
 */
public class RevisionWorkflowManager {
    private static final int MAX_RETRIES_FOR_REVISION_REQUEST = 5;
    private static final int MAX_INFERENCES_PER_REQUEST = 50;
    private static final int POLL_INTERVAL_MS = 1000;
    private static final int MAX_POLL_ATTEMPTS = 300;

    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final ZenyardOptions options;

    public RevisionWorkflowManager(PluginTool tool, BinariesApi binariesApi, ZenyardOptions options) {
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.options = options;
    }

    public UUID getOrRegisterBinary(Program program, TaskMonitor monitor) {
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        String existingBinaryId = props.getString("binary_id");
        if (existingBinaryId != null && !existingBinaryId.isEmpty()) {
            try {
                return UUID.fromString(existingBinaryId);
            } catch (IllegalArgumentException e) {
                // continue to register
            }
        }

        ApiClient apiClient = ZenyardApiClientFactory.createApiClient(options);
        BinariesApi tempBinariesApi = new BinariesApi(apiClient);
        RegisterBinaryTask registerTask = new RegisterBinaryTask(tool, tempBinariesApi, options, "",
            null, program);
        tool.execute(registerTask);

        String binaryIdStr = null;
        for (int i = 0; i < 600; i++) {
            if (monitor.isCancelled()) {
                throw new RuntimeException("Binary registration cancelled");
            }
            ZenyardProgramProperties currentProps = new ZenyardProgramProperties(program);
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
        return UUID.fromString(binaryIdStr);
    }

    public int getCurrentRevision(ZenyardProgramProperties props) {
        Integer revision = props.getInt("revision");
        if (revision != null) {
            return revision;
        }
        return 1;
    }

    public boolean validateFunction(com.zenyard.ghidra.api.generated.model.Function func) {
        try {
            if (func.getCode() == null || func.getCode().isEmpty()) {
                return false;
            }
            if (func.getRanges() != null) {
                String code = func.getCode();
                for (Range range : func.getRanges()) {
                    if (range.getStart() < 0 || range.getStart() + range.getLength() > code.length()) {
                        return false;
                    }
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @FunctionalInterface
    public interface ApiRequest {
        void execute() throws Exception;
    }

    public <T> T retryApiRequest(Callable<T> request) {
        return retryApiCall(request, MAX_RETRIES_FOR_REVISION_REQUEST);
    }

    public <T> T retryApiCall(Callable<T> request, int maxRetries) {
        int retries = 0;
        while (retries < maxRetries) {
            try {
                return request.call();
            } catch (Exception e) {
                retries++;
                if (retries >= maxRetries) {
                    throw new RuntimeException("Failed after " + maxRetries + " retries", e);
                }
                long delayMs = 100L * (1L << (retries - 1));
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Interrupted during retry", ie);
                }
            }
        }
        throw new RuntimeException("Failed after " + maxRetries + " retries");
    }

    public void executeApiRequest(ApiRequest request) {
        retryApiRequest(() -> {
            CompletableFuture.supplyAsync(() -> {
                try {
                    request.execute();
                    return null;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }).get();
            return null;
        });
    }

    public void createRevision(UUID binaryId, int revisionNumber) {
        CreateRevisionParams createParams = new CreateRevisionParams();
        createParams.setNumber(revisionNumber);
        executeApiRequest(() -> binariesApi.createRevision(binaryId, createParams));
    }

    public void addObjectsToRevision(UUID binaryId, List<ModelObject> objects) {
        AddObjectsToCurrentRevisionParams addParams = new AddObjectsToCurrentRevisionParams();
        addParams.setObjects(objects);
        executeApiRequest(() -> binariesApi.addObjectsToCurrentRevision(binaryId, addParams));
    }

    public void finishAndAnalyzeRevision(UUID binaryId, boolean analyzeDependents) {
        FinishAndAnalyzeCurrentRevisionBody finishParams = new FinishAndAnalyzeCurrentRevisionBody();
        finishParams.setAnalyzeDependents(analyzeDependents);
        executeApiRequest(() -> binariesApi.finishAndAnalyzeCurrentRevision(binaryId, finishParams));
    }

    public List<MaybeUnknownInference> pollForInferences(TaskMonitor monitor, UUID binaryId, int revisionNumber) {
        List<MaybeUnknownInference> allInferences = new ArrayList<>();
        Integer cursor = null;
        int pollAttempts = 0;

        while (pollAttempts < MAX_POLL_ATTEMPTS && !monitor.isCancelled()) {
            try {
                GetInferencesResponse response = binariesApi.getInferences(
                    revisionNumber, binaryId, cursor, MAX_INFERENCES_PER_REQUEST);
                if (response.getInferences() != null) {
                    allInferences.addAll(response.getInferences());
                }
                if (!response.getHasNext()) {
                    break;
                }
                cursor = response.getCursor();
                pollAttempts++;
            } catch (Exception e) {
                Msg.debug(this, "Retrying inference polling: " + e.getMessage());
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
}
