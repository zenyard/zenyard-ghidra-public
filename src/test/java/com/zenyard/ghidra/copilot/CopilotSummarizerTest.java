package com.zenyard.ghidra.copilot;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.TokenCountEstimator;
import dev.langchain4j.model.chat.StreamingChatModel;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.chat.response.StreamingChatResponseHandler;

class CopilotSummarizerTest {

    @Test
    void compactMessagesSummarizesOlderConversationWhenBudgetIsTight() {
        String summary = "## Goal\nAnalyze auth flow\n## Key Findings\n- Found sink"
            + "\n## Important Artifacts\n- FUN_401000\n## Open Questions\n- Caller path"
            + "\n## Next Steps\n- Trace xrefs";
        CopilotSummarizer summarizer = new CopilotSummarizer(
            new StubStreamingChatModel(summary),
            new CharCountEstimator()
        );

        List<ChatMessage> messages = List.of(
            SystemMessage.from("System prompt"),
            UserMessage.from(repeat("User asks for a broad binary review. ", 20)),
            AiMessage.from(repeat("Assistant proposes a long plan. ", 20)),
            UserMessage.from(repeat("Tool-heavy follow-up with function names and notes. ", 18)),
            AiMessage.from(repeat("Assistant summarizes findings and addresses. ", 18)),
            UserMessage.from("Keep this recent question intact."),
            AiMessage.from("Keep this recent answer intact.")
        );

        CopilotSummarizer.CompactionResult result = summarizer.compactMessages(
            messages,
            new CopilotSummarizer.CompactionRequest(220, 0.8, 4, 5000, 0, false, 2),
            null
        );

        assertTrue(result.compacted());
        assertTrue(result.estimatedTokensAfter() < result.estimatedTokensBefore());
        assertTrue(result.messages().stream()
            .filter(UserMessage.class::isInstance)
            .map(UserMessage.class::cast)
            .anyMatch(message -> message.singleText().contains("Conversation summary from earlier turns")));
        assertTrue(result.messages().stream()
            .anyMatch(message -> message.toString().contains("Keep this recent answer intact.")));
    }

    @Test
    void compactMessagesForceCompactionRunsOneSummaryPassForRetry() {
        String summary = "## Goal\nRetry summary\n## Key Findings\n- Reduced context"
            + "\n## Important Artifacts\n- retry\n## Open Questions\n- none"
            + "\n## Next Steps\n- continue";
        CopilotSummarizer summarizer = new CopilotSummarizer(
            new StubStreamingChatModel(summary),
            new CharCountEstimator()
        );

        List<ChatMessage> messages = List.of(
            SystemMessage.from("System prompt"),
            UserMessage.from("Earlier context that should be compacted."),
            AiMessage.from("Earlier assistant context that should be compacted."),
            UserMessage.from("Second earlier context that should also be compacted."),
            AiMessage.from("Second earlier assistant context that should also be compacted."),
            UserMessage.from("Recent question"),
            AiMessage.from("Recent answer")
        );

        CopilotSummarizer.CompactionResult result = summarizer.compactMessages(
            messages,
            new CopilotSummarizer.CompactionRequest(10_000, 0.95, 4, 5000, 0, true, 1),
            null
        );

        assertTrue(result.compacted());
        assertTrue(result.passes() >= 1);
    }

    private static String repeat(String text, int count) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < count; i++) {
            builder.append(text);
        }
        return builder.toString();
    }

    private static final class CharCountEstimator implements TokenCountEstimator {
        @Override
        public int estimateTokenCountInText(String text) {
            return text == null ? 0 : Math.max(1, text.length() / 4);
        }

        @Override
        public int estimateTokenCountInMessage(ChatMessage message) {
            return estimateTokenCountInText(String.valueOf(message));
        }

        @Override
        public int estimateTokenCountInMessages(Iterable<ChatMessage> messages) {
            int total = 0;
            for (ChatMessage message : messages) {
                total += estimateTokenCountInMessage(message);
            }
            return total;
        }
    }

    private static final class StubStreamingChatModel implements StreamingChatModel {
        private final String responseText;

        private StubStreamingChatModel(String responseText) {
            this.responseText = responseText;
        }

        @Override
        public void chat(String message, StreamingChatResponseHandler handler) {
            handler.onCompleteResponse(ChatResponse.builder()
                .aiMessage(AiMessage.from(responseText))
                .build());
        }
    }
}
