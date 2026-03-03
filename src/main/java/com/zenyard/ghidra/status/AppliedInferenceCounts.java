package com.zenyard.ghidra.status;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Immutable snapshot of applied inference result counts, grouped into
 * user-facing categories.
 *
 * Mirrors decompai_ida.ui._status_bar_format.PendingInferenceCounts.
 */
public final class AppliedInferenceCounts {

    private final int functions;
    private final int globalVariables;
    private final int swiftSources;
    private final int signatureModifications;
    private final int structModifications;

    private AppliedInferenceCounts(int functions, int globalVariables,
            int swiftSources, int signatureModifications, int structModifications) {
        this.functions = functions;
        this.globalVariables = globalVariables;
        this.swiftSources = swiftSources;
        this.signatureModifications = signatureModifications;
        this.structModifications = structModifications;
    }

    /**
     * Build from raw per-type counts keyed by Java class simple name
     * (e.g. "FunctionOverview", "Name", "ParameterType").
     */
    public static AppliedInferenceCounts fromRawCounts(Map<String, Integer> counts) {
        int functionOverview = counts.getOrDefault("FunctionOverview", 0);
        int nameCount = counts.getOrDefault("Name", 0);

        return new AppliedInferenceCounts(
            functionOverview,
            Math.max(nameCount - functionOverview, 0),
            counts.getOrDefault("SwiftFunction", 0),
            counts.getOrDefault("ParameterType", 0) + counts.getOrDefault("ReturnType", 0),
            counts.getOrDefault("StructDefinition", 0)
        );
    }

    public int getTotal() {
        return functions + globalVariables + swiftSources
            + signatureModifications + structModifications;
    }

    public int getFunctions() {
        return functions;
    }

    public int getGlobalVariables() {
        return globalVariables;
    }

    public int getSwiftSources() {
        return swiftSources;
    }

    public int getSignatureModifications() {
        return signatureModifications;
    }

    public int getStructModifications() {
        return structModifications;
    }

    /**
     * Format as an HTML tooltip for Swing, with bullet lines per non-zero
     * category. Returns {@code null} when all counts are zero.
     */
    public String formatTooltip() {
        List<String> lines = new ArrayList<>();
        if (functions > 0) {
            lines.add("\u2022 " + formatCompactCount(functions) + " functions");
        }
        if (globalVariables > 0) {
            lines.add("\u2022 " + formatCompactCount(globalVariables) + " global variables");
        }
        if (swiftSources > 0) {
            lines.add("\u2022 " + formatCompactCount(swiftSources) + " Swift sources");
        }
        if (signatureModifications > 0) {
            lines.add("\u2022 " + formatCompactCount(signatureModifications) + " signature modifications");
        }
        if (structModifications > 0) {
            lines.add("\u2022 " + formatCompactCount(structModifications) + " struct modifications");
        }
        if (lines.isEmpty()) {
            return null;
        }
        return "<html>" + String.join("<br>", lines) + "</html>";
    }

    public static String formatCompactCount(int n) {
        if (n >= 1_000_000) {
            return String.format("%.1fM", n / 1_000_000.0);
        }
        if (n >= 1_000) {
            return String.format("%.1fK", n / 1_000.0);
        }
        return String.valueOf(n);
    }
}
