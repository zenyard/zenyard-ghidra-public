package com.zenyard.ghidra.usage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.model.UnlimitedUsage;
import com.zenyard.ghidra.api.generated.model.UsageResponse;

class UsageStateTest {

    @Test
    void fromApiErrorMapsQuotaExceededWithNestedDetail() {
        String body = "{\"detail\":{\"type\":\"quota_exceeded\",\"usage_percentage\":100}}";
        UsageState state = UsageState.fromApiError(402, body);

        assertEquals(UsageState.Kind.LIMITED, state.getKind());
        assertEquals(1.0, state.getUsagePercentage());
        assertTrue(state.isBlocked());
    }

    @Test
    void fromApiErrorNormalizesPercentageScale() {
        String body = "{\"usage_percentage\":150}";
        UsageState state = UsageState.fromApiError(402, body);

        assertEquals(UsageState.Kind.LIMITED, state.getKind());
        assertEquals(1.5, state.getUsagePercentage());
        assertTrue(state.isBlocked());
    }

    @Test
    void fromApiErrorUsesFallbackWhenBodyMissing() {
        UsageState state = UsageState.fromApiError(402, "");

        assertEquals(UsageState.Kind.LIMITED, state.getKind());
        assertEquals(1.0, state.getUsagePercentage());
        assertTrue(state.isBlocked());
    }

    @Test
    void fromApiErrorMapsNoPlanToExpired() {
        UsageState state = UsageState.fromApiError(404, "{\"detail\":\"no available plans\"}");

        assertEquals(UsageState.Kind.EXPIRED, state.getKind());
        assertTrue(state.isBlocked());
    }

    @Test
    void fromApiErrorKeepsNonUsageCodesUnknown() {
        UsageState state = UsageState.fromApiError(403, "{\"detail\":\"Missing API KEY\"}");

        assertEquals(UsageState.Kind.UNKNOWN, state.getKind());
    }

    @Test
    void unlimitedUsageIsVisibleInStatusBar() {
        UsageResponse response = new UsageResponse();
        response.setActualInstance(new UnlimitedUsage());

        UsageState state = UsageState.fromUsageResponse(response);
        assertEquals(UsageState.Kind.UNLIMITED, state.getKind());
        assertTrue(state.isVisible());
        assertEquals("Usage: Unlimited", state.getDisplayText());
    }
}
