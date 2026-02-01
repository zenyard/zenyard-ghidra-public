package com.zenyard.ghidra.upload;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

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
    private final BinariesApi binariesApi;
    private final Program program;
    
    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean binaryRegistered = false;
    private volatile boolean shouldStop = false;
    private UUID binaryId = null;
    
    public UploadOriginalFilesTask(PluginTool tool, 
                                  BinariesApi binariesApi, StatusBarManager statusBarManager,
                                  Program program, EventDispatcher eventDispatcher) {
        super("Upload Original File", true, false, false, eventDispatcher, statusBarManager, TASK_ID, STATUS_BAR_PRIORITY);
        this.tool = tool;
        this.binariesApi = binariesApi;
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

                // Upload file
                CompletableFuture.supplyAsync(() -> {
                    try {
                        // Convert byte array to File for upload
                        File tempFile = File.createTempFile("binary_upload_", ".bin");
                        Files.write(tempFile.toPath(), serialized.getData());
                        try {
                            binariesApi.putOriginalFile(serialized.getName(), binaryId, tempFile, serialized.getType());
                        } finally {
                            tempFile.delete();
                        }
                        return null;
                    } catch (IOException | ApiException e) {
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
    
}
