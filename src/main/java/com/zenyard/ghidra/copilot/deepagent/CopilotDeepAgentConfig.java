package com.zenyard.ghidra.copilot.deepagent;

import java.util.Collection;
import java.util.Set;

import org.bsc.langgraph4j.checkpoint.BaseCheckpointSaver;

/**
 * Runtime controls for deep-agent orchestration.
 */
public record CopilotDeepAgentConfig(
        int recursionLimit,
        boolean debug,
        Set<String> returnDirectTools,
        boolean parallelToolExecution,
        int parallelToolMaxConcurrency,
        long responseStreamingTimeoutMs,
        String threadId,
        BaseCheckpointSaver checkpointSaver,
        Set<String> interruptsBefore,
        Set<String> interruptsAfter,
        boolean releaseThread,
        boolean interruptBeforeEdge,
        String graphId,
        int contextWindowTokens,
        double summarizationTriggerFraction,
        int summarizationKeepMessages,
        int toolArgTruncateThreshold,
        int requestTokenReserveTokens,
        int promptTooLongRetryExtraReserveTokens,
        boolean promptTooLongCompactionRetryEnabled,
        long subAgentTimeoutMs,
        int subAgentRecursionLimit,
        long toolCallTimeoutMs) {

    public CopilotDeepAgentConfig {
        if (recursionLimit <= 0) {
            recursionLimit = 1000;
        }
        returnDirectTools = returnDirectTools != null ? Set.copyOf(returnDirectTools) : Set.of();
        if (parallelToolMaxConcurrency <= 0) {
            parallelToolMaxConcurrency = 4;
        }
        if (responseStreamingTimeoutMs <= 0) {
            responseStreamingTimeoutMs = 120_000L;
        }
        threadId = (threadId != null && !threadId.isBlank()) ? threadId : "copilot";
        interruptsBefore = interruptsBefore != null ? Set.copyOf(interruptsBefore) : Set.of();
        interruptsAfter = interruptsAfter != null ? Set.copyOf(interruptsAfter) : Set.of();
        graphId = (graphId != null && !graphId.isBlank()) ? graphId : "copilot-deepagent";
        if (contextWindowTokens <= 0) {
            contextWindowTokens = 200_000;
        }
        if (summarizationTriggerFraction <= 0 || summarizationTriggerFraction > 1.0) {
            summarizationTriggerFraction = 0.8;
        }
        if (summarizationKeepMessages <= 0) {
            summarizationKeepMessages = 20;
        }
        if (toolArgTruncateThreshold <= 0) {
            toolArgTruncateThreshold = 5000;
        }
        if (requestTokenReserveTokens <= 0) {
            requestTokenReserveTokens = 4000;
        }
        if (promptTooLongRetryExtraReserveTokens <= 0) {
            promptTooLongRetryExtraReserveTokens = 12000;
        }
        if (subAgentTimeoutMs <= 0) {
            subAgentTimeoutMs = 540_000L;
        }
        if (subAgentRecursionLimit <= 0) {
            subAgentRecursionLimit = 50;
        }
        if (toolCallTimeoutMs <= 0) {
            toolCallTimeoutMs = 60_000L;
        }
    }

    public static CopilotDeepAgentConfig defaults() {
        return new CopilotDeepAgentConfig(
            1000,
            false,
            Set.of(),
            false,
            4,
            120_000L,
            "copilot",
            null,
            Set.of(),
            Set.of(),
            false,
            false,
            "copilot-deepagent",
            200_000,
            0.8,
            20,
            5000,
            4000,
            12000,
            true,
            540_000L,
            50,
            60_000L
        );
    }

    public static Set<String> normalizeNodeIds(Collection<String> nodeIds) {
        if (nodeIds == null || nodeIds.isEmpty()) {
            return Set.of();
        }
        return nodeIds.stream()
            .filter(v -> v != null && !v.isBlank())
            .map(String::trim)
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }
}
