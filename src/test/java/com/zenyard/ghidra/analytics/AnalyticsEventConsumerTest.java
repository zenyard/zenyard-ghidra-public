package com.zenyard.ghidra.analytics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.api.AnalyticsApi;
import com.zenyard.ghidra.api.generated.model.AnalysisAcceptedEvent;
import com.zenyard.ghidra.api.generated.model.AnalysisSource;
import com.zenyard.ghidra.api.generated.model.AnalysisType;
import com.zenyard.ghidra.api.generated.model.CopilotClearRequestedEvent;
import com.zenyard.ghidra.api.generated.model.CopilotMessageSentEvent;
import com.zenyard.ghidra.api.generated.model.CopilotOpenEvent;
import com.zenyard.ghidra.api.generated.model.CopilotStopRequestedEvent;
import com.zenyard.ghidra.api.generated.model.DatabaseOpenedEvent;
import com.zenyard.ghidra.api.generated.model.InitialAnalysisDismissedEvent;
import com.zenyard.ghidra.api.generated.model.PausedDialgBoxUserResponse;
import com.zenyard.ghidra.api.generated.model.PluginLoadedEvent;
import com.zenyard.ghidra.api.generated.model.QuotaExhaustedDialogShownEvent;
import com.zenyard.ghidra.api.generated.model.QuotaExhaustedDialogShownReason;
import com.zenyard.ghidra.api.generated.model.TrackEventRequest;
import com.zenyard.ghidra.api.generated.model.TrackEventResponse;
import com.zenyard.ghidra.config.PluginConfiguration;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.ZenyardEvent.EventType;

/**
 * Unit tests for {@link AnalyticsEventConsumer}.
 * Uses a {@link RecordingAnalyticsApi} stub (no Mockito) injected via the
 * package-private constructor, matching the manual-stub pattern used elsewhere.
 */
class AnalyticsEventConsumerTest {

    /** Captures every call to {@code trackEvent()} without touching the network. */
    private static final class RecordingAnalyticsApi extends AnalyticsApi {
        final List<TrackEventRequest> captured = new ArrayList<>();
        private CountDownLatch latch = new CountDownLatch(0);

        void expectOne() {
            latch = new CountDownLatch(1);
        }

        void await() throws InterruptedException {
            assertTrue(latch.await(2, TimeUnit.SECONDS), "analytics call did not complete in time");
        }

        @Override
        public TrackEventResponse trackEvent(TrackEventRequest req) {
            captured.add(req);
            latch.countDown();
            return new TrackEventResponse();
        }
    }

    private EventDispatcher dispatcher;
    private RecordingAnalyticsApi api;
    private AnalyticsEventConsumer consumer;

    @BeforeEach
    void setUp() {
        dispatcher = new EventDispatcher();
        api = new RecordingAnalyticsApi();
        consumer = new AnalyticsEventConsumer(api, buildConfig(true));
        dispatcher.subscribe(consumer);
    }

    // ---- helpers ----------------------------------------------------------

    private static PluginConfiguration buildConfig(boolean analyticsEnabled) {
        return new PluginConfiguration(
            "https://api.zenyard.ai", "", "INFO",
            true, true, true, true, 0,
            null, null, null, null,
            "test-install-id", analyticsEnabled);
    }

    private void publish(EventType type) {
        dispatcher.publish(new ZenyardEvent(type, "test"));
    }

    private Object innerEvent(int index) {
        return api.captured.get(index).getEvent().getActualInstance();
    }

    // ---- tests ------------------------------------------------------------

    @Test
    void trackPluginLoaded_sendsPluginLoadedEvent() throws InterruptedException {
        api.expectOne();
        consumer.trackPluginLoaded();
        api.await();

        assertEquals(1, api.captured.size());
        assertInstanceOf(PluginLoadedEvent.class, innerEvent(0));
    }

    @Test
    void databaseOpened_extractsFileNameAndFileSize() throws InterruptedException {
        api.expectOne();
        dispatcher.publish(ZenyardEvent.builder(EventType.DATABASE_OPENED, "test")
            .withPayload("file_name", "binary.bin")
            .withPayload("file_size", 1024L)
            .build());
        api.await();

        assertEquals(1, api.captured.size());
        DatabaseOpenedEvent event = (DatabaseOpenedEvent) innerEvent(0);
        assertEquals("binary.bin", event.getFileName());
        assertEquals(BigDecimal.valueOf(1024L), event.getFileSize());
    }

    @Test
    void initialDialogConfirmed_alone_buffersEventWithoutSending() {
        publish(EventType.INITIAL_DIALOG_CONFIRMED);

        assertTrue(api.captured.isEmpty(), "event must be held until binary_id arrives");
    }

    @Test
    void deferredPairing_confirmedThenBinaryId_sendsAnalysisAcceptedWithAllFields()
            throws InterruptedException {
        UUID binaryId = UUID.randomUUID();

        dispatcher.publish(ZenyardEvent.builder(EventType.INITIAL_DIALOG_CONFIRMED, "test")
            .withPayload("start_source", AnalysisSource.NEW_FILE_OPEN.getValue())
            .withPayload("analysis_type", AnalysisType.INITIAL_ANALYSIS.getValue())
            .withPayload("user_prompt", Boolean.TRUE)
            .build());
        assertTrue(api.captured.isEmpty(), "no event before binary_id");

        api.expectOne();
        dispatcher.publish(ZenyardEvent.builder(EventType.BINARY_ID_AVAILABLE, "test")
            .withPayload("binaryId", binaryId)
            .build());
        api.await();

        assertEquals(1, api.captured.size());
        AnalysisAcceptedEvent event = (AnalysisAcceptedEvent) innerEvent(0);
        assertEquals(AnalysisSource.NEW_FILE_OPEN, event.getStartSource());
        assertEquals(AnalysisType.INITIAL_ANALYSIS, event.getAnalysisType());
        assertEquals(Boolean.TRUE, event.getUserPrompt());
        assertEquals(binaryId, event.getBinaryId());
    }

    @Test
    void initialDialogDismissed_sendsInitialAnalysisDismissedEvent() throws InterruptedException {
        api.expectOne();
        publish(EventType.INITIAL_DIALOG_DISMISSED);
        api.await();

        assertEquals(1, api.captured.size());
        assertInstanceOf(InitialAnalysisDismissedEvent.class, innerEvent(0));
    }

    @Test
    void analysisRerunRequested_usesToolbarSourceAndExtractsBinaryId() throws InterruptedException {
        String binaryId = UUID.randomUUID().toString();
        api.expectOne();
        dispatcher.publish(ZenyardEvent.builder(EventType.ANALYSIS_RERUN_REQUESTED, "test")
            .withPayload("binary_id", binaryId)
            .build());
        api.await();

        assertEquals(1, api.captured.size());
        AnalysisAcceptedEvent event = (AnalysisAcceptedEvent) innerEvent(0);
        assertEquals(AnalysisSource.TOOLBAR_ICON_REQUEST, event.getStartSource());
        assertEquals(UUID.fromString(binaryId), event.getBinaryId());
    }

    @Test
    void copilotOpened_sendsCopilotOpenEvent() throws InterruptedException {
        api.expectOne();
        publish(EventType.COPILOT_OPENED);
        api.await();

        assertEquals(1, api.captured.size());
        assertInstanceOf(CopilotOpenEvent.class, innerEvent(0));
    }

    @Test
    void copilotMessageSent_extractsAllThreeFields() throws InterruptedException {
        api.expectOne();
        dispatcher.publish(ZenyardEvent.builder(EventType.COPILOT_MESSAGE_SENT, "test")
            .withPayload("input_length_chars", 42)
            .withPayload("thread_id", "t1")
            .withPayload("message_index", 3)
            .build());
        api.await();

        assertEquals(1, api.captured.size());
        CopilotMessageSentEvent event = (CopilotMessageSentEvent) innerEvent(0);
        assertEquals(42, event.getInputLengthChars());
        assertEquals("t1", event.getThreadId());
        assertEquals(3, event.getMessageIndex());
    }

    @Test
    void copilotClearRequested_sendsCopilotClearRequestedEvent() throws InterruptedException {
        api.expectOne();
        publish(EventType.COPILOT_CLEAR_REQUESTED);
        api.await();

        assertEquals(1, api.captured.size());
        assertInstanceOf(CopilotClearRequestedEvent.class, innerEvent(0));
    }

    @Test
    void copilotStopRequested_sendsCopilotStopRequestedEvent() throws InterruptedException {
        api.expectOne();
        publish(EventType.COPILOT_STOP_REQUESTED);
        api.await();

        assertEquals(1, api.captured.size());
        assertInstanceOf(CopilotStopRequestedEvent.class, innerEvent(0));
    }

    @Test
    void quotaExhaustedDialogShown_extractsShowReasonAndUserResponse() throws InterruptedException {
        api.expectOne();
        dispatcher.publish(ZenyardEvent.builder(EventType.QUOTA_EXHAUSTED_DIALOG_SHOWN, "test")
            .withPayload("show_reason", QuotaExhaustedDialogShownReason.AUTOMATIC.getValue())
            .withPayload("user_response", PausedDialgBoxUserResponse.CANCEL.getValue())
            .build());
        api.await();

        assertEquals(1, api.captured.size());
        QuotaExhaustedDialogShownEvent event = (QuotaExhaustedDialogShownEvent) innerEvent(0);
        assertEquals(QuotaExhaustedDialogShownReason.AUTOMATIC, event.getShowReason());
        assertEquals(PausedDialgBoxUserResponse.CANCEL, event.getUserResponse());
    }

    @Test
    void analyticsDisabled_suppressesAllCalls() {
        AnalyticsEventConsumer disabled = new AnalyticsEventConsumer(api, buildConfig(false));
        dispatcher.unsubscribe(consumer);
        dispatcher.subscribe(disabled);

        publish(EventType.COPILOT_OPENED);

        assertTrue(api.captured.isEmpty());
    }

    @Test
    void environmentMetadata_presentOnEveryEvent() throws InterruptedException {
        api.expectOne();
        publish(EventType.COPILOT_OPENED);
        api.await();

        assertEquals(1, api.captured.size());
        var env = api.captured.get(0).getEnvironment();
        assertNotNull(env);
        assertNotNull(env.getSessionId());
        assertNotNull(env.getOsType());
        assertNotNull(env.getPluginVersion());
    }

    @Test
    void pendingStateCleared_afterPairing_subsequentBinaryIdProducesNoEvent()
            throws InterruptedException {
        UUID binaryId = UUID.randomUUID();

        // Complete a pairing
        dispatcher.publish(ZenyardEvent.builder(EventType.INITIAL_DIALOG_CONFIRMED, "test")
            .withPayload("start_source", AnalysisSource.NEW_FILE_OPEN.getValue())
            .build());
        api.expectOne();
        dispatcher.publish(ZenyardEvent.builder(EventType.BINARY_ID_AVAILABLE, "test")
            .withPayload("binaryId", binaryId)
            .build());
        api.await();
        assertEquals(1, api.captured.size());
        api.captured.clear();

        // Second BINARY_ID_AVAILABLE with no preceding INITIAL_DIALOG_CONFIRMED
        dispatcher.publish(ZenyardEvent.builder(EventType.BINARY_ID_AVAILABLE, "test")
            .withPayload("binaryId", UUID.randomUUID())
            .build());

        assertTrue(api.captured.isEmpty(), "pending was consumed; no second event expected");
    }
}
