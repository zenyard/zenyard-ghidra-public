package com.zenyard.ghidra.status;

/**
 * Minimal no-op stub of {@link StatusBarManager} for unit tests that need to
 * avoid the Ghidra UI dependency.  Subclass and override the recording methods
 * in individual tests.
 */
class StatusBarManagerStub extends StatusBarManager {

    StatusBarManagerStub() {
        super(null, null);
    }

    @Override
    public void registerTask(String taskId, int priority) {
        // no-op in stub
    }

    @Override
    public void updateTaskStatus(String taskId, String status, Integer progress, boolean indeterminate) {
        // no-op in stub
    }

    @Override
    public void updateTaskStatus(String taskId, String status, Integer progress,
            boolean indeterminate, String tooltip) {
        // no-op in stub
    }

    @Override
    public void unregisterTask(String taskId) {
        // no-op in stub
    }
}
