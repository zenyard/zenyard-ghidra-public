package com.zenyard.ghidra.polling;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.model.BinaryState;
import com.zenyard.ghidra.api.generated.model.BinaryStatePaused;
import com.zenyard.ghidra.api.generated.model.BinaryStateQueued;
import com.zenyard.ghidra.api.generated.model.BinaryStateReady;
import com.zenyard.ghidra.api.generated.model.BinaryStateUninitialized;
import com.zenyard.ghidra.api.generated.model.BinaryStatus;

/**
 * Verifies that {@link PollServerStatusTask#extractIsPaused} correctly
 * identifies the paused state from the generated {@link BinaryStatus}
 * discriminated union.
 */
class ExtractIsPausedTest {

    @Test
    void returnsTrueWhenPaused() {
        BinaryStatus status = new BinaryStatus();
        status.setState(new BinaryState(new BinaryStatePaused()));

        assertTrue(PollServerStatusTask.extractIsPaused(status));
    }

    @Test
    void returnsFalseWhenReady() {
        BinaryStatus status = new BinaryStatus();
        status.setState(new BinaryState(new BinaryStateReady()));

        assertFalse(PollServerStatusTask.extractIsPaused(status));
    }

    @Test
    void returnsFalseWhenQueued() {
        BinaryStateQueued queued = new BinaryStateQueued();
        queued.setQueuePosition(3);

        BinaryStatus status = new BinaryStatus();
        status.setState(new BinaryState(queued));

        assertFalse(PollServerStatusTask.extractIsPaused(status));
    }

    @Test
    void returnsFalseWhenUninitialized() {
        BinaryStatus status = new BinaryStatus();
        status.setState(new BinaryState(new BinaryStateUninitialized()));

        assertFalse(PollServerStatusTask.extractIsPaused(status));
    }

    @Test
    void returnsFalseWhenStatusIsNull() {
        assertFalse(PollServerStatusTask.extractIsPaused(null));
    }

    @Test
    void returnsFalseWhenStateIsNull() {
        BinaryStatus status = new BinaryStatus();
        status.setState(null);

        assertFalse(PollServerStatusTask.extractIsPaused(status));
    }
}
