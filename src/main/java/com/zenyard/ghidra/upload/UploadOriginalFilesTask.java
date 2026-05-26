package com.zenyard.ghidra.upload;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.channels.Channels;
import java.nio.channels.Pipe;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import com.zenyard.ghidra.api.generated.ApiClient;
import com.zenyard.ghidra.api.generated.ApiException;
import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.status.StatusBarManager;
import com.zenyard.ghidra.status.StatusBarPriorities;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.tasks.StatusBarAwareTask;
import com.zenyard.ghidra.util.BinarySerializer;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import org.apache.http.HttpEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;

/**
 * Background task to upload original binary file.
 * Waits for BINARY_REGISTERED event, then uploads files and publishes UPLOAD_ORIGINAL_FILES_COMPLETE.
 *
 * NOTE: mirrors zenyard_ida/upload_original_files_task.py
 */
public class UploadOriginalFilesTask extends StatusBarAwareTask {

    private static final String TASK_ID = "upload_original_files";
    private static final int STATUS_BAR_PRIORITY = StatusBarPriorities.UPLOAD_ORIGINAL_FILES;

    private final PluginTool tool;
    private final ApiClient apiClient;
    private final Program program;

    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean binaryRegistered = false;
    private volatile boolean shouldStop = false;
    private UUID binaryId = null;

    public UploadOriginalFilesTask(PluginTool tool,
                                  BinariesApi binariesApi, StatusBarManager statusBarManager,
                                  Program program, EventDispatcher eventDispatcher) {
        this(tool, binariesApi, null, statusBarManager, program, eventDispatcher);
    }

    public UploadOriginalFilesTask(PluginTool tool,
                                  BinariesApi binariesApi, ApiClient apiClient,
                                  StatusBarManager statusBarManager,
                                  Program program, EventDispatcher eventDispatcher) {
        super("Upload Original File", true, false, false, eventDispatcher, statusBarManager, TASK_ID, STATUS_BAR_PRIORITY);
        this.tool = tool;
        this.apiClient = apiClient;
        this.program = program;
    }

    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        Set<ZenyardEvent.EventType> types = new HashSet<>();
        types.add(ZenyardEvent.EventType.BINARY_REGISTERED);
        types.add(ZenyardEvent.EventType.PROGRAM_DEACTIVATED);
        return types;
    }

    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.BINARY_REGISTERED) {
            UUID eventBinaryId = event.getPayloadValue("binaryId", UUID.class);
            if (eventBinaryId != null) {
                synchronized (waitLock) {
                    this.binaryId = eventBinaryId;
                    this.binaryRegistered = true;
                    waitLock.notify();
                }
            } else {
                // Fallback: get from properties
                ZenyardProgramProperties props = new ZenyardProgramProperties(program);
                String binaryIdStr = props.getString("binary_id");
                if (binaryIdStr != null && !binaryIdStr.isEmpty()) {
                    try {
                        synchronized (waitLock) {
                            this.binaryId = UUID.fromString(binaryIdStr);
                            this.binaryRegistered = true;
                            waitLock.notify();
                        }
                    } catch (IllegalArgumentException e) {
                        // Invalid UUID format
                    }
                }
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
            // Check if already uploaded
            ZenyardProgramProperties props = new ZenyardProgramProperties(program);
            String uploaded = props.getString("original_files_uploaded");
            if ("true".equals(uploaded)) {
                // Already uploaded, publish event and skip
                publishEvent(new ZenyardEvent(ZenyardEvent.EventType.UPLOAD_ORIGINAL_FILES_COMPLETE, getTaskTitle()));
                return;
            }

            // Check if binary ID is already available
            String binaryIdStr = props.getString("binary_id");
            if (binaryIdStr != null && !binaryIdStr.isEmpty()) {
                try {
                    this.binaryId = UUID.fromString(binaryIdStr);
                    this.binaryRegistered = true;
                } catch (IllegalArgumentException e) {
                    // Invalid UUID format, wait for event
                }
            }

            // Wait for BINARY_REGISTERED event
            if (!binaryRegistered) {
                synchronized (waitLock) {
                    while (!binaryRegistered && !monitor.isCancelled() && !shouldStop) {
                        // Re-check properties periodically
                        binaryIdStr = props.getString("binary_id");
                        if (binaryIdStr != null && !binaryIdStr.isEmpty()) {
                            try {
                                this.binaryId = UUID.fromString(binaryIdStr);
                                this.binaryRegistered = true;
                                break;
                            } catch (IllegalArgumentException e) {
                                // Invalid UUID format, continue waiting
                            }
                        }

                        try {
                            waitLock.wait(1000); // Wait up to 1 second, then check again
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }
                }
            }

            if (binaryId == null || monitor.isCancelled() || shouldStop) {
                return;
            }

            runWithStatusBar(() -> {
                StatusBarManager statusBarManager = getStatusBarManager();
                if (statusBarManager != null) {
                    statusBarManager.updateTaskStatus(TASK_ID, "Serializing binary file...", null, true);
                }

                // Serialize binary
                BinarySerializer.SerializedBinary serialized = BinarySerializer.serializeBinary(program);

                if (statusBarManager != null) {
                    statusBarManager.updateTaskStatus(TASK_ID, "Uploading binary file...", null, true);
                }

                // Upload raw bytes — the server stores and later gzip-decompresses this data.
                CompletableFuture.supplyAsync(() -> {
                    try {
                        putOriginalFileBinary(binaryId, serialized.getName(), serialized.getData(), serialized.getType());
                        return null;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }).get();

                // Mark as uploaded
                props.setString("original_files_uploaded", "true");

                // Publish UPLOAD_ORIGINAL_FILES_COMPLETE event
                publishEvent(new ZenyardEvent(ZenyardEvent.EventType.UPLOAD_ORIGINAL_FILES_COMPLETE, getTaskTitle()));
            });

        } catch (Exception e) {
            Msg.showError(this, tool.getActiveWindow(), "Upload Error",
                "Failed to upload original file: " + e.getMessage(), e);
            throw new RuntimeException("Failed to upload original file", e);
        }
    }

    /**
     * Upload raw binary bytes to the server's original_files endpoint.
     * Uses a binary multipart part so the server receives and stores the exact
     * gzip bytes that it later decompresses during analysis.
     */
    private void putOriginalFileBinary(UUID binaryId, String name, byte[] data, String type) throws Exception {
        if (apiClient == null) {
            throw new IllegalStateException("ApiClient required for binary upload");
        }

        String path = "/binaries/" + ApiClient.urlEncode(binaryId.toString())
                + "/original_files/" + ApiClient.urlEncode(name)
                + "?type=" + ApiClient.urlEncode(type);

        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        builder.addBinaryBody("data", data, ContentType.APPLICATION_OCTET_STREAM, name);
        HttpEntity entity = builder.build();

        // Stream the multipart body via a pipe to avoid buffering the entire payload.
        Pipe pipe = Pipe.open();
        new Thread(() -> {
            try (OutputStream out = Channels.newOutputStream(pipe.sink())) {
                entity.writeTo(out);
            } catch (IOException e) {
                Msg.error(this, "Error writing multipart body: " + e.getMessage());
            }
        }).start();

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(apiClient.getBaseUri() + path))
                .header("Content-Type", entity.getContentType().getValue())
                .header("Accept", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofInputStream(() -> Channels.newInputStream(pipe.source())));

        if (apiClient.getRequestInterceptor() != null) {
            apiClient.getRequestInterceptor().accept(requestBuilder);
        }

        HttpResponse<String> response = apiClient.getHttpClient()
                .send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() / 100 != 2) {
            throw new ApiException(response.statusCode(),
                    "putOriginalFile call failed with: " + response.statusCode() + " - " + response.body());
        }
    }
}
