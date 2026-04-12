package com.zenyard.ghidra.copilot.deepagent;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.ToolExecutionResultMessage;
import dev.langchain4j.data.message.UserMessage;

/**
 * Context window management: truncates and summarizes message history
 * to prevent exceeding model token limits.
 */
public final class MessageSummarizer {

    private MessageSummarizer() {}

    /**
     * Approximate token count by dividing character count by 4.
     */
    public static int estimateTokens(List<ChatMessage> messages) {
        int totalChars = 0;
        for (ChatMessage message : messages) {
            totalChars += messageCharCount(message);
        }
        return totalChars / 4;
    }

    public static int estimateTextTokens(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        return text.length() / 4;
    }

    public static int estimateToolSpecificationTokens(List<ToolSpecification> toolSpecifications) {
        if (toolSpecifications == null || toolSpecifications.isEmpty()) {
            return 0;
        }
        int totalChars = 0;
        for (ToolSpecification specification : toolSpecifications) {
            if (specification != null) {
                totalChars += specification.toString().length();
            }
        }
        return totalChars / 4;
    }

    /**
     * Truncate message history if the estimated token count exceeds the threshold.
     * Keeps the system message (first), the last N messages, and replaces
     * older messages with a summary placeholder.
     *
     * Also truncates large tool result arguments in older messages.
     *
     * @param messages the full message list
     * @param contextWindowTokens total model context window in tokens
     * @param triggerFraction fraction of context window that triggers summarization (e.g. 0.8)
     * @param keepMessages number of recent messages to keep verbatim
     * @param toolArgTruncateThreshold max chars for tool arguments in older messages
     * @return the (possibly truncated) message list
     */
    public static List<ChatMessage> maybeTruncate(
            List<ChatMessage> messages,
            int contextWindowTokens,
            double triggerFraction,
            int keepMessages,
            int toolArgTruncateThreshold) {
        return maybeTruncate(
            messages,
            contextWindowTokens,
            triggerFraction,
            keepMessages,
            toolArgTruncateThreshold,
            0);
    }

    public static List<ChatMessage> maybeTruncate(
            List<ChatMessage> messages,
            int contextWindowTokens,
            double triggerFraction,
            int keepMessages,
            int toolArgTruncateThreshold,
            int reservedTokens) {
        if (messages == null || messages.isEmpty()) {
            return messages;
        }

        int estimatedTokens = estimateTokens(messages);
        int threshold = Math.max(1, (int) (contextWindowTokens * triggerFraction) - Math.max(0, reservedTokens));

        if (estimatedTokens < threshold) {
            return messages;
        }

        ghidra.util.Msg.debug(MessageSummarizer.class,
            "MessageSummarizer triggered: estimatedTokens=" + estimatedTokens
            + " threshold=" + threshold
            + " reservedTokens=" + Math.max(0, reservedTokens)
            + " messageCount=" + messages.size());

        // Separate system message (if first) from conversation messages
        ChatMessage firstMessage = messages.get(0);
        boolean hasSystem = firstMessage instanceof SystemMessage;
        int conversationStart = hasSystem ? 1 : 0;

        List<ChatMessage> conversation = messages.subList(conversationStart, messages.size());
        int conversationSize = conversation.size();

        if (conversationSize <= keepMessages) {
            // Not enough messages to summarize; just truncate tool args
            return truncateToolArgs(messages, toolArgTruncateThreshold);
        }

        // Split into older (to summarize) and recent (to keep)
        int splitIndex = conversationSize - keepMessages;
        List<ChatMessage> olderMessages = conversation.subList(0, splitIndex);
        List<ChatMessage> recentMessages = conversation.subList(splitIndex, conversationSize);

        // Build summary of older messages
        int olderTokens = estimateTokens(olderMessages);
        int olderToolCalls = countToolMessages(olderMessages);
        String summary = "[Conversation summary: " + olderMessages.size() + " messages"
            + " (~" + olderTokens + " tokens) truncated."
            + " Included " + olderToolCalls + " tool interactions.]";

        // Reassemble
        List<ChatMessage> result = new ArrayList<>();
        if (hasSystem) {
            result.add(firstMessage);
        }
        result.add(UserMessage.from(summary));
        result.addAll(truncateToolArgsInList(recentMessages, toolArgTruncateThreshold));

        ghidra.util.Msg.debug(MessageSummarizer.class,
            "MessageSummarizer result: " + messages.size() + " -> " + result.size() + " messages"
            + " (~" + estimateTokens(result) + " tokens)");

        return result;
    }

    private static List<ChatMessage> truncateToolArgs(List<ChatMessage> messages, int threshold) {
        List<ChatMessage> result = new ArrayList<>(messages.size());
        for (ChatMessage message : messages) {
            result.add(maybeTruncateToolArg(message, threshold));
        }
        return result;
    }

    public static List<ChatMessage> truncateToolArgsInList(List<ChatMessage> messages, int threshold) {
        List<ChatMessage> result = new ArrayList<>(messages.size());
        for (ChatMessage message : messages) {
            result.add(maybeTruncateToolArg(message, threshold));
        }
        return result;
    }

    private static ChatMessage maybeTruncateToolArg(ChatMessage message, int threshold) {
        if (threshold <= 0) {
            return message;
        }
        String type = message.type().name();
        if (!"TOOL_EXECUTION_RESULT".equals(type) && !"TOOL".equals(type)) {
            return message;
        }
        String content = MessageSanitizer.extractToolResultText(message);
        if (content.length() <= threshold) {
            return message;
        }
        String toolName = MessageSanitizer.extractToolName(message);
        String truncated = content.substring(0, threshold)
            + "\n...[truncated, len=" + content.length() + "]";
        if (message instanceof ToolExecutionResultMessage resultMessage) {
            String id = resultMessage.id() != null ? resultMessage.id() : "";
            String name = !toolName.isEmpty() ? toolName : resultMessage.toolName();
            if (!id.isEmpty()) {
                return new ToolExecutionResultMessage(id, name, truncated);
            }
            return message;
        }
        String toolId = MessageSanitizer.extractToolExecutionId(message);
        if (!toolId.isEmpty()) {
            return new ToolExecutionResultMessage(toolId, toolName, truncated);
        }
        return message;
    }

    private static int messageCharCount(ChatMessage message) {
        if (message == null) {
            return 0;
        }
        Object text = MessageSanitizer.tryInvoke(message, "text");
        if (text != null) {
            return String.valueOf(text).length();
        }
        Object content = MessageSanitizer.tryInvoke(message, "content");
        if (content != null) {
            return String.valueOf(content).length();
        }
        return message.toString().length();
    }

    private static int countToolMessages(List<ChatMessage> messages) {
        int count = 0;
        for (ChatMessage message : messages) {
            String type = message.type().name();
            if ("TOOL_EXECUTION_RESULT".equals(type) || "TOOL".equals(type)) {
                count++;
            }
        }
        return count;
    }
}
