package com.zenyard.decompai.ghidra.upload;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import com.zenyard.decompai.ghidra.api.generated.api.BinariesApi;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.events.EventDispatcher;
import com.zenyard.decompai.ghidra.tasks.EventAwareTask;
import com.zenyard.decompai.ghidra.status.StatusBarManager;
import com.zenyard.decompai.ghidra.util.BinarySerializer;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Background task to upload original binary file.
 * Waits for BINARY_REGISTERED event, then uploads files and publishes UPLOAD_ORIGINAL_FILES_COMPLETE.
 * 
 * NOTE: mirrors decompai_ida/upload_original_files_task.py
 */
public class UploadOriginalFilesTask extends EventAwareTask {
    
    private static final String TASK_ID = "upload_original_files";
    private static final int STATUS_BAR_PRIORITY = com.zenyard.decompai.ghidra.status.StatusBarPriorities.UPLOAD_ORIGINAL_FILES;
    
    private final PluginTool tool;
    private final BinariesApi binariesApi;
    private final StatusBarManager statusBarManager;
    private final Program program;
    
    // Event waiting
    private final Object waitLock = new Object();
    private volatile boolean binaryRegistered = false;
    private volatile boolean shouldStop = false;
    private UUID binaryId = null;
    
    public UploadOriginalFilesTask(PluginTool tool, 
                                  BinariesApi binariesApi, StatusBarManager statusBarManager,
                                  Program program, EventDispatcher eventDispatcher) {
        super("Upload Original File", true, false, false, eventDispatcher);
        this.tool = tool;
        this.binariesApi = binariesApi;
        this.statusBarManager = statusBarManager;
        this.program = program;
    }
    
    @Override
    public Set<DecompaiEvent.EventType> getSubscribedEventTypes() {
        Set<DecompaiEvent.EventType> types = new HashSet<>();
        types.add(DecompaiEvent.EventType.BINARY_REGISTERED);
        types.add(DecompaiEvent.EventType.PROGRAM_DEACTIVATED);
        return types;
    }
    
    @Override
    public void handleEvent(DecompaiEvent event) {
        if (event.getType() == DecompaiEvent.EventType.BINARY_REGISTERED) {
            UUID eventBinaryId = event.getPayloadValue("binaryId", UUID.class);
            if (eventBinaryId != null) {
                synchronized (waitLock) {
                    this.binaryId = eventBinaryId;
                    this.binaryRegistered = true;
                    waitLock.notify();
                }
            } else {
                // Fallback: get from properties
                com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties props = 
                    new com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties(program);
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
            // Check if already uploaded
            com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties props = 
                new com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties(program);
            String uploaded = props.getString("original_files_uploaded");
            if ("true".equals(uploaded)) {
                // Already uploaded, publish event and skip
                publishEvent(new DecompaiEvent(DecompaiEvent.EventType.UPLOAD_ORIGINAL_FILES_COMPLETE, getTaskTitle()));
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
            
            // Register with status bar
            if (statusBarManager != null) {
                statusBarManager.registerTask(TASK_ID, STATUS_BAR_PRIORITY);
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
                    java.io.File tempFile = java.io.File.createTempFile("binary_upload_", ".bin");
                    java.nio.file.Files.write(tempFile.toPath(), serialized.getData());
                    try {
                        binariesApi.putOriginalFile(serialized.getName(), binaryId, tempFile, serialized.getType());
                    } finally {
                        tempFile.delete();
                    }
                    return null;
                } catch (java.io.IOException | com.zenyard.decompai.ghidra.api.generated.ApiException e) {
                    throw new RuntimeException(e);
                }
            }).get();
            
            // Mark as uploaded
            props.setString("original_files_uploaded", "true");
            
            // Publish UPLOAD_ORIGINAL_FILES_COMPLETE event
            publishEvent(new DecompaiEvent(DecompaiEvent.EventType.UPLOAD_ORIGINAL_FILES_COMPLETE, getTaskTitle()));
            
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(TASK_ID);
            }
            
        } catch (Exception e) {
            Msg.showError(this, tool.getActiveWindow(), "Upload Error",
                "Failed to upload original file: " + e.getMessage(), e);
            if (statusBarManager != null) {
                statusBarManager.unregisterTask(TASK_ID);
            }
            throw new RuntimeException("Failed to upload original file", e);
        }
    }
    
}
