package com.zenyard.ghidra.status;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.events.ZenyardEvent;

/**
 * Unit tests for {@link QueuePositionMonitor}.
 * Uses a recording stub instead of the real {@link StatusBarManager} to
 * verify register / update / unregister calls without Ghidra UI dependencies.
 */
class QueuePositionMonitorTest {

    /** Lightweight recording of StatusBarManager calls. */
    private static final class RecordingStatusBarManager extends StatusBarManagerStub {
        final List<String> calls = new ArrayList<>();
        private boolean taskRegistered = false;

        boolean isTaskRegistered() {
            return taskRegistered;
        }

        @Override
        public void registerTask(String taskId, int priority) {
            calls.add("register:" + taskId + ":" + priority);
            taskRegistered = true;
        }

        @Override
        public void updateTaskStatus(String taskId, String status, Integer progress, boolean indeterminate) {
            calls.add("update:" + taskId + ":" + status + ":" + progress + ":" + indeterminate);
        }

        @Override
        public void unregisterTask(String taskId) {
            calls.add("unregister:" + taskId);
            taskRegistered = false;
        }
    }

    private EventDispatcher dispatcher;
    private RecordingStatusBarManager recorder;
    private QueuePositionMonitor monitor;

    @BeforeEach
    void setUp() {
        dispatcher = new EventDispatcher();
        recorder = new RecordingStatusBarManager();
        monitor = new QueuePositionMonitor(recorder, dispatcher);
    }

    // ---- helpers ----------------------------------------------------------

    private void publishQueuePosition(Integer position) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("queuePosition", position);
        dispatcher.publish(new ZenyardEvent(
            ZenyardEvent.EventType.QUEUE_POSITION_UPDATED, "test", payload));
    }

    private void publishProgramDeactivated() {
        dispatcher.publish(new ZenyardEvent(
            ZenyardEvent.EventType.PROGRAM_DEACTIVATED, "test"));
    }

    // ---- tests -----------------------------------------------------------

    @Test
    void registersAndShowsStatusWhenQueuePositionIsPositive() {
        publishQueuePosition(3);

        assertEquals(2, recorder.calls.size(), "expect register + update");
        assertEquals("register:" + QueuePositionMonitor.TASK_ID + ":38", recorder.calls.get(0));
        assertTrue(recorder.calls.get(1).contains("In queue (3 remaining)"));
        assertTrue(recorder.isTaskRegistered());
    }

    @Test
    void updatesWithoutReRegisteringOnSubsequentPositions() {
        publishQueuePosition(3);
        recorder.calls.clear();

        publishQueuePosition(2);

        assertEquals(1, recorder.calls.size(), "only update, no re-register");
        assertTrue(recorder.calls.get(0).contains("In queue (2 remaining)"));
        assertTrue(recorder.isTaskRegistered());
    }

    @Test
    void unregistersWhenQueuePositionBecomesNull() {
        publishQueuePosition(3);
        recorder.calls.clear();

        publishQueuePosition(null);

        assertEquals(1, recorder.calls.size());
        assertEquals("unregister:" + QueuePositionMonitor.TASK_ID, recorder.calls.get(0));
        assertFalse(recorder.isTaskRegistered());
    }

    @Test
    void zeroPositionTreatedAsNotQueued() {
        publishQueuePosition(0);

        assertTrue(recorder.calls.isEmpty(), "zero should not register");
        assertFalse(recorder.isTaskRegistered());
    }

    @Test
    void negativePositionTreatedAsNotQueued() {
        publishQueuePosition(-1);

        assertTrue(recorder.calls.isEmpty());
        assertFalse(recorder.isTaskRegistered());
    }

    @Test
    void programDeactivatedUnregistersIfRegistered() {
        publishQueuePosition(5);
        recorder.calls.clear();

        publishProgramDeactivated();

        assertEquals(1, recorder.calls.size());
        assertEquals("unregister:" + QueuePositionMonitor.TASK_ID, recorder.calls.get(0));
        assertFalse(recorder.isTaskRegistered());
    }

    @Test
    void programDeactivatedIsNoOpWhenNotRegistered() {
        publishProgramDeactivated();

        assertTrue(recorder.calls.isEmpty());
    }

    @Test
    void disposeUnsubscribesAndUnregisters() {
        publishQueuePosition(4);
        recorder.calls.clear();

        monitor.dispose();

        assertEquals(1, recorder.calls.size(), "dispose should unregister");
        assertEquals("unregister:" + QueuePositionMonitor.TASK_ID, recorder.calls.get(0));

        // Further events should not reach the monitor
        recorder.calls.clear();
        publishQueuePosition(1);
        assertTrue(recorder.calls.isEmpty(), "disposed monitor should not react");
    }

    @Test
    void nullPayloadTreatedAsNotQueued() {
        Map<String, Object> payload = new HashMap<>();
        // queuePosition key absent
        dispatcher.publish(new ZenyardEvent(
            ZenyardEvent.EventType.QUEUE_POSITION_UPDATED, "test", payload));

        assertTrue(recorder.calls.isEmpty());
    }
}
