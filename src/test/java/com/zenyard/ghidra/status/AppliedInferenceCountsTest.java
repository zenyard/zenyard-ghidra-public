package com.zenyard.ghidra.status;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

class AppliedInferenceCountsTest {

    @Test
    void fromRawCountsMapsFieldsCorrectly() {
        Map<String, Integer> raw = new HashMap<>();
        raw.put("FunctionOverview", 10);
        raw.put("Name", 15);
        raw.put("SwiftFunction", 3);
        raw.put("ParameterType", 4);
        raw.put("ReturnType", 2);
        raw.put("StructDefinition", 7);

        AppliedInferenceCounts counts = AppliedInferenceCounts.fromRawCounts(raw);

        assertEquals(10, counts.getFunctions());
        assertEquals(5, counts.getGlobalVariables()); // 15 - 10
        assertEquals(3, counts.getSwiftSources());
        assertEquals(6, counts.getSignatureModifications()); // 4 + 2
        assertEquals(7, counts.getStructModifications());
        assertEquals(31, counts.getTotal());
    }

    @Test
    void globalVariablesClampedToZero() {
        Map<String, Integer> raw = new HashMap<>();
        raw.put("FunctionOverview", 20);
        raw.put("Name", 5);

        AppliedInferenceCounts counts = AppliedInferenceCounts.fromRawCounts(raw);

        assertEquals(0, counts.getGlobalVariables());
    }

    @Test
    void emptyRawCountsGivesZeroTotal() {
        AppliedInferenceCounts counts = AppliedInferenceCounts.fromRawCounts(Map.of());

        assertEquals(0, counts.getTotal());
        assertNull(counts.formatTooltip());
    }

    @Test
    void formatTooltipSkipsZeroCounts() {
        Map<String, Integer> raw = Map.of(
            "FunctionOverview", 100,
            "StructDefinition", 5
        );

        AppliedInferenceCounts counts = AppliedInferenceCounts.fromRawCounts(raw);
        String tooltip = counts.formatTooltip();

        assertTrue(tooltip.contains("100 functions"));
        assertTrue(tooltip.contains("5 struct modifications"));
        assertTrue(!tooltip.contains("global variables"));
        assertTrue(!tooltip.contains("Swift sources"));
        assertTrue(!tooltip.contains("signature modifications"));
    }

    @Test
    void formatTooltipWrapsHtml() {
        Map<String, Integer> raw = Map.of("FunctionOverview", 1);

        String tooltip = AppliedInferenceCounts.fromRawCounts(raw).formatTooltip();

        assertTrue(tooltip.startsWith("<html>"));
        assertTrue(tooltip.endsWith("</html>"));
    }

    @Test
    void formatCompactCountThresholds() {
        assertEquals("0", AppliedInferenceCounts.formatCompactCount(0));
        assertEquals("999", AppliedInferenceCounts.formatCompactCount(999));
        assertEquals("1.0K", AppliedInferenceCounts.formatCompactCount(1_000));
        assertEquals("1.5K", AppliedInferenceCounts.formatCompactCount(1_500));
        assertEquals("999.9K", AppliedInferenceCounts.formatCompactCount(999_900));
        assertEquals("1.0M", AppliedInferenceCounts.formatCompactCount(1_000_000));
        assertEquals("2.3M", AppliedInferenceCounts.formatCompactCount(2_300_000));
    }

    @Test
    void unknownRawKeysAreIgnored() {
        Map<String, Integer> raw = Map.of(
            "FunctionOverview", 5,
            "VariablesMapping", 100,
            "NotSwift", 50
        );

        AppliedInferenceCounts counts = AppliedInferenceCounts.fromRawCounts(raw);

        assertEquals(5, counts.getTotal());
    }
}
