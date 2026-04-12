package com.zenyard.ghidra.analytics;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import ghidra.framework.Application;
import ghidra.util.Msg;

import com.zenyard.ghidra.api.generated.ApiClient;
import com.zenyard.ghidra.api.generated.api.AnalyticsApi;
import com.zenyard.ghidra.api.generated.model.AnalysisAcceptedEvent;
import com.zenyard.ghidra.api.generated.model.AnalysisSource;
import com.zenyard.ghidra.api.generated.model.AnalysisType;
import com.zenyard.ghidra.api.generated.model.CopilotClearRequestedEvent;
import com.zenyard.ghidra.api.generated.model.CopilotMessageSentEvent;
import com.zenyard.ghidra.api.generated.model.CopilotOpenEvent;
import com.zenyard.ghidra.api.generated.model.CopilotStopRequestedEvent;
import com.zenyard.ghidra.api.generated.model.DatabaseOpenedEvent;
import com.zenyard.ghidra.api.generated.model.DecompilerEnum;
import com.zenyard.ghidra.api.generated.model.Event;
import com.zenyard.ghidra.api.generated.model.ExtraDetails;
import com.zenyard.ghidra.api.generated.model.InitialAnalysisDismissedEvent;
import com.zenyard.ghidra.api.generated.model.OSEnum;
import com.zenyard.ghidra.api.generated.model.PausedDialgBoxUserResponse;
import com.zenyard.ghidra.api.generated.model.PluginLoadedEvent;
import com.zenyard.ghidra.api.generated.model.QuotaExhaustedDialogShownEvent;
import com.zenyard.ghidra.api.generated.model.QuotaExhaustedDialogShownReason;
import com.zenyard.ghidra.api.generated.model.TrackEventRequest;
import com.zenyard.ghidra.config.PluginConfiguration;
import com.zenyard.ghidra.events.EventConsumer;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.events.ZenyardEvent.EventType;

/**
 * Translates internal ZenyardEvent bus events into analytics API calls.
 * Runs fire-and-forget via CompletableFuture; failures are logged at DEBUG level.
 */
public class AnalyticsEventConsumer implements EventConsumer {

    private static final Set<EventType> SUBSCRIBED_TYPES = EnumSet.of(
        EventType.DATABASE_OPENED,
        EventType.INITIAL_DIALOG_CONFIRMED,
        EventType.BINARY_ID_AVAILABLE,
        EventType.INITIAL_DIALOG_DISMISSED,
        EventType.ANALYSIS_RERUN_REQUESTED,
        EventType.COPILOT_OPENED,
        EventType.COPILOT_MESSAGE_SENT,
        EventType.COPILOT_CLEAR_REQUESTED,
        EventType.COPILOT_STOP_REQUESTED,
        EventType.QUOTA_EXHAUSTED_DIALOG_SHOWN
    );

    private final AnalyticsApi analyticsApi;
    private final ExtraDetails environment;
    private final boolean analyticsEnabled;
    /** Buffered pending event waiting for a binary ID to arrive. */
    private volatile AnalysisAcceptedEvent pendingAnalysisEvent = null;

    public AnalyticsEventConsumer(ApiClient apiClient, PluginConfiguration config) {
        this.analyticsApi = new AnalyticsApi(apiClient);
        this.analyticsEnabled = config.isAnalyticsEnabled();
        this.environment = buildEnvironment(config);
    }

    /** Package-private constructor for tests — allows injecting a stub {@link AnalyticsApi}. */
    AnalyticsEventConsumer(AnalyticsApi analyticsApi, PluginConfiguration config) {
        this.analyticsApi = analyticsApi;
        this.analyticsEnabled = config.isAnalyticsEnabled();
        this.environment = buildEnvironment(config);
    }

    private static ExtraDetails buildEnvironment(PluginConfiguration config) {
        String sessionId = UUID.randomUUID().toString();
        String installId = config.getInstallId();

        String ghidraVersion;
        try {
            ghidraVersion = Application.getApplicationVersion();
        } catch (Exception e) {
            ghidraVersion = "unknown";
        }

        OSEnum osType = detectOsType();
        String osVersion = System.getProperty("os.version", "unknown");
        String pluginVersion = readPluginVersion();

        return new ExtraDetails()
            .decompiler(DecompilerEnum.GHIDRA)
            .decompilerVersion(ghidraVersion)
            .osType(osType)
            .osVersion(osVersion)
            .pluginVersion(pluginVersion)
            .installId(installId)
            .sessionId(sessionId);
    }

    private static OSEnum detectOsType() {
        String osName = System.getProperty("os.name", "").toLowerCase();
        if (osName.contains("windows")) {
            return OSEnum.WINDOWS;
        } else if (osName.contains("mac")) {
            return OSEnum.MAC_OS;
        } else if (osName.contains("linux")) {
            return OSEnum.LINUX;
        }
        return OSEnum.UNKNOWN;
    }

    private static String readPluginVersion() {
        try (InputStream is = AnalyticsEventConsumer.class.getResourceAsStream("/extension.properties")) {
            if (is == null) {
                return "unknown";
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("version=")) {
                        return line.substring("version=".length()).trim();
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(AnalyticsEventConsumer.class, "Could not read plugin version: " + e.getMessage());
        }
        return "unknown";
    }

    @Override
    public Set<EventType> getSubscribedEventTypes() {
        return SUBSCRIBED_TYPES;
    }

    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event == null) {
            return;
        }
        switch (event.getType()) {
            case DATABASE_OPENED:
                handleDatabaseOpened(event);
                break;
            case INITIAL_DIALOG_CONFIRMED:
                handleInitialDialogConfirmed(event);
                break;
            case BINARY_ID_AVAILABLE:
                handleBinaryIdAvailable(event);
                break;
            case INITIAL_DIALOG_DISMISSED:
                send(new Event(new InitialAnalysisDismissedEvent()
                    .timestamp(nowSeconds())));
                break;
            case ANALYSIS_RERUN_REQUESTED:
                handleAnalysisRerunRequested(event);
                break;
            case COPILOT_OPENED:
                send(new Event(new CopilotOpenEvent()
                    .timestamp(nowSeconds())));
                break;
            case COPILOT_MESSAGE_SENT:
                handleCopilotMessageSent(event);
                break;
            case COPILOT_CLEAR_REQUESTED:
                send(new Event(new CopilotClearRequestedEvent()
                    .timestamp(nowSeconds())));
                break;
            case COPILOT_STOP_REQUESTED:
                send(new Event(new CopilotStopRequestedEvent()
                    .timestamp(nowSeconds())));
                break;
            case QUOTA_EXHAUSTED_DIALOG_SHOWN:
                handleQuotaExhaustedDialogShown(event);
                break;
            default:
                break;
        }
    }

    /**
     * Fires the "Plugin - Loaded" event directly (not via the event bus).
     * Call this once after the consumer is subscribed.
     */
    public void trackPluginLoaded() {
        send(new Event(new PluginLoadedEvent()
            .timestamp(nowSeconds())
            .coldStart(true)));
    }

    private void handleDatabaseOpened(ZenyardEvent event) {
        String fileName = event.getPayloadValue("file_name", String.class);
        Long fileSize = event.getPayloadValue("file_size", Long.class);
        DatabaseOpenedEvent apiEvent = new DatabaseOpenedEvent()
            .timestamp(nowSeconds())
            .fileName(fileName != null ? fileName : "");
        if (fileSize != null) {
            apiEvent.fileSize(BigDecimal.valueOf(fileSize));
        }
        send(new Event(apiEvent));
    }

    private void handleInitialDialogConfirmed(ZenyardEvent event) {
        String startSourceStr = event.getPayloadValue("start_source", String.class);
        String analysisTypeStr = event.getPayloadValue("analysis_type", String.class);
        Boolean userPrompt = event.getPayloadValue("user_prompt", Boolean.class);
        String binaryIdStr = event.getPayloadValue("binary_id", String.class);

        AnalysisSource startSource = parseAnalysisSource(startSourceStr);
        AnalysisType analysisType = parseAnalysisType(analysisTypeStr);

        AnalysisAcceptedEvent apiEvent = new AnalysisAcceptedEvent()
            .timestamp(nowSeconds())
            .startSource(startSource != null ? startSource : AnalysisSource.NEW_FILE_OPEN)
            .analysisType(analysisType != null ? analysisType : AnalysisType.INITIAL_ANALYSIS)
            .userPrompt(userPrompt != null ? userPrompt : Boolean.FALSE);

        if (binaryIdStr != null && !binaryIdStr.isBlank()) {
            try {
                apiEvent.binaryId(UUID.fromString(binaryIdStr));
                send(new Event(apiEvent));
                return;
            } catch (IllegalArgumentException ignored) {
                // skip invalid UUID
            }
        }

        // No binary ID yet — buffer and wait for BINARY_ID_AVAILABLE
        pendingAnalysisEvent = apiEvent;
    }

    private void handleBinaryIdAvailable(ZenyardEvent event) {
        AnalysisAcceptedEvent pending = pendingAnalysisEvent;
        if (pending == null) {
            return;
        }
        pendingAnalysisEvent = null;

        UUID binaryId = event.getPayloadValue("binaryId", UUID.class);
        if (binaryId != null) {
            pending.binaryId(binaryId);
        }
        send(new Event(pending));
    }

    private void handleQuotaExhaustedDialogShown(ZenyardEvent event) {
        String showReasonStr = event.getPayloadValue("show_reason", String.class);
        String userResponseStr = event.getPayloadValue("user_response", String.class);

        QuotaExhaustedDialogShownEvent apiEvent = new QuotaExhaustedDialogShownEvent()
            .timestamp(nowSeconds());

        if (showReasonStr != null) {
            try {
                apiEvent.showReason(QuotaExhaustedDialogShownReason.fromValue(showReasonStr));
            } catch (IllegalArgumentException ignored) {
                // skip unknown enum value
            }
        }
        if (userResponseStr != null) {
            try {
                apiEvent.userResponse(PausedDialgBoxUserResponse.fromValue(userResponseStr));
            } catch (IllegalArgumentException ignored) {
                // skip unknown enum value
            }
        }
        send(new Event(apiEvent));
    }

    private void handleAnalysisRerunRequested(ZenyardEvent event) {
        String binaryIdStr = event.getPayloadValue("binary_id", String.class);

        AnalysisAcceptedEvent apiEvent = new AnalysisAcceptedEvent()
            .timestamp(nowSeconds())
            .startSource(AnalysisSource.TOOLBAR_ICON_REQUEST)
            .analysisType(AnalysisType.CHANGES_DETECTED)
            .userPrompt(Boolean.FALSE);

        if (binaryIdStr != null && !binaryIdStr.isBlank()) {
            try {
                apiEvent.binaryId(UUID.fromString(binaryIdStr));
            } catch (IllegalArgumentException ignored) {
                // skip invalid UUID
            }
        }
        send(new Event(apiEvent));
    }

    private void handleCopilotMessageSent(ZenyardEvent event) {
        Integer inputLength = event.getPayloadValue("input_length_chars", Integer.class);
        String threadId = event.getPayloadValue("thread_id", String.class);
        Integer messageIndex = event.getPayloadValue("message_index", Integer.class);

        send(new Event(new CopilotMessageSentEvent()
            .timestamp(nowSeconds())
            .inputLengthChars(inputLength != null ? inputLength : 0)
            .threadId(threadId != null ? threadId : "")
            .messageIndex(messageIndex != null ? messageIndex : 0)));
    }

    private void send(Event event) {
        if (!analyticsEnabled) {
            return;
        }
        TrackEventRequest req = new TrackEventRequest()
            .event(event)
            .environment(environment);
        CompletableFuture.runAsync(() -> {
            try {
                analyticsApi.trackEvent(req);
            } catch (Exception e) {
                Msg.debug(this, "Analytics send failed: " + e.getMessage());
            }
        });
    }

    private static int nowSeconds() {
        return (int) (System.currentTimeMillis() / 1000);
    }

    private static AnalysisSource parseAnalysisSource(String value) {
        if (value == null) {
            return null;
        }
        for (AnalysisSource s : AnalysisSource.values()) {
            if (s.getValue().equals(value)) {
                return s;
            }
        }
        return null;
    }

    private static AnalysisType parseAnalysisType(String value) {
        if (value == null) {
            return null;
        }
        for (AnalysisType t : AnalysisType.values()) {
            if (t.getValue().equals(value)) {
                return t;
            }
        }
        return null;
    }
}
