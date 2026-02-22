package com.zenyard.ghidra.usage;

import java.awt.Component;
import java.math.BigDecimal;

import com.zenyard.ghidra.api.generated.model.ExpiredUsage;
import com.zenyard.ghidra.api.generated.model.LimitedUsage;
import com.zenyard.ghidra.api.generated.model.UnlimitedUsage;
import com.zenyard.ghidra.api.generated.model.UsageResponse;
import ghidra.util.Msg;

public final class UsageState {
    public static final String BLOCKED_DIALOG_TITLE = "Usage Limit Reached";

    public enum Kind {
        UNKNOWN,
        UNLIMITED,
        LIMITED,
        EXPIRED
    }

    private final Kind kind;
    private final Double usagePercentage;
    private final String expiration;

    private UsageState(Kind kind, Double usagePercentage, String expiration) {
        this.kind = kind;
        this.usagePercentage = usagePercentage;
        this.expiration = expiration;
    }

    public static UsageState unknown() {
        return new UsageState(Kind.UNKNOWN, null, null);
    }

    public static UsageState fromUsageResponse(UsageResponse response) {
        if (response == null || response.getActualInstance() == null) {
            return UsageState.unknown();
        }
        Object actual = response.getActualInstance();
        if (actual instanceof LimitedUsage) {
            LimitedUsage limited = (LimitedUsage) actual;
            BigDecimal percentage = limited.getUsagePercentage();
            Double value = percentage != null ? percentage.doubleValue() : null;
            return new UsageState(Kind.LIMITED, value, null);
        }
        if (actual instanceof ExpiredUsage) {
            return new UsageState(Kind.EXPIRED, null, null);
        }
        if (actual instanceof UnlimitedUsage) {
            return new UsageState(Kind.UNLIMITED, null, null);
        }
        return UsageState.unknown();
    }

    public Kind getKind() {
        return kind;
    }

    public Double getUsagePercentage() {
        return usagePercentage;
    }

    public String getExpiration() {
        return expiration;
    }

    public boolean isVisible() {
        if (kind == Kind.LIMITED) {
            return usagePercentage != null;
        }
        return kind == Kind.EXPIRED;
    }

    public UsageLevel getDisplayLevel() {
        if (kind == Kind.EXPIRED) {
            return UsageLevel.EXPIRED;
        }
        if (kind == Kind.LIMITED && usagePercentage != null && usagePercentage >= 1.0) {
            return UsageLevel.OVER_LIMIT;
        }
        return UsageLevel.NORMAL;
    }

    public String getDisplayText() {
        if (!isVisible()) {
            return "";
        }
        if (kind == Kind.EXPIRED) {
            return "EXPIRED";
        }
        if (kind == Kind.LIMITED && usagePercentage != null) {
            if (usagePercentage >= 1.0) {
                return "Usage: 100%";
            }
            int percent = (int) Math.round(usagePercentage * 100.0);
            if (percent < 0) {
                percent = 0;
            }
            if (percent > 100) {
                percent = 100;
            }
            return "Usage: " + percent + "%";
        }
        return "";
    }

    public String getTooltip() {
        if (kind == Kind.EXPIRED) {
            return "Your plan has expired. Upgrade or contact us to continue.";
        }
        if (kind == Kind.LIMITED && usagePercentage != null) {
            if (usagePercentage >= 1.0) {
                return "You've used all your analysis quota. Upgrade or contact us to continue.";
            }
            return "Percent of your analysis quota used so far";
        }
        return "";
    }

    public boolean isBlocked() {
        return kind == Kind.EXPIRED || (kind == Kind.LIMITED && usagePercentage != null && usagePercentage >= 1.0);
    }

    public String getBlockedMessage() {
        String tooltip = getTooltip();
        return tooltip.isEmpty() ? "Usage limit reached. Upgrade or contact us to continue." : tooltip;
    }

    public static void showBlockedDialog(Component parent, UsageState state) {
        UsageState resolved = state != null ? state : UsageState.unknown();
        Msg.showError(UsageState.class, parent, BLOCKED_DIALOG_TITLE, resolved.getBlockedMessage(), null);
    }

    public String getPlanLabel() {
        switch (kind) {
            case UNLIMITED:
                return "Unlimited";
            case LIMITED:
                return "Limited";
            case EXPIRED:
                return "Expired";
            default:
                return "Unknown";
        }
    }
}
