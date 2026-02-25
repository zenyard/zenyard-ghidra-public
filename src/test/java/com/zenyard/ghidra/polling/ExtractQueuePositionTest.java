package com.zenyard.ghidra.polling;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.model.BinaryState;
import com.zenyard.ghidra.api.generated.model.BinaryStatePaused;
import com.zenyard.ghidra.api.generated.model.BinaryStateQueued;
import com.zenyard.ghidra.api.generated.model.BinaryStateReady;
import com.zenyard.ghidra.api.generated.model.BinaryStateUninitialized;
import com.zenyard.ghidra.api.generated.model.BinaryStatus;

/**
 * Verifies that {@link PollServerStatusTask#extractQueuePosition} correctly
 * maps the generated {@link BinaryStatus} discriminated union to the queue
 * position integer.
 */
class ExtractQueuePositionTest {

    @Test
    void returnsPositionWhenQueued() {
        BinaryStateQueued queued = new BinaryStateQueued();
        queued.setQueuePosition(5);

        BinaryStatus status = new BinaryStatus();
        status.setState(new BinaryState(queued));

        assertEquals(5, PollServerStatusTask.extractQueuePosition(status));
    }

    @Test
    void returnsNullWhenReady() {
        BinaryStatus status = new BinaryStatus();
        status.setState(new BinaryState(new BinaryStateReady()));

        assertNull(PollServerStatusTask.extractQueuePosition(status));
    }

    @Test
    void returnsNullWhenPaused() {
        BinaryStatus status = new BinaryStatus();
        status.setState(new BinaryState(new BinaryStatePaused()));

        assertNull(PollServerStatusTask.extractQueuePosition(status));
    }

    @Test
    void returnsNullWhenUninitialized() {
        BinaryStatus status = new BinaryStatus();
        status.setState(new BinaryState(new BinaryStateUninitialized()));

        assertNull(PollServerStatusTask.extractQueuePosition(status));
    }

    @Test
    void returnsNullWhenStatusIsNull() {
        assertNull(PollServerStatusTask.extractQueuePosition(null));
    }

    @Test
    void returnsNullWhenStateIsNull() {
        BinaryStatus status = new BinaryStatus();
        status.setState(null);

        assertNull(PollServerStatusTask.extractQueuePosition(status));
    }
}
