package com.zenyard.ghidra.usage;

import java.awt.Component;
import java.awt.Desktop;
import java.math.BigDecimal;
import java.net.URI;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.zenyard.ghidra.api.generated.model.ExpiredUsage;
import com.zenyard.ghidra.api.generated.model.LimitedUsage;
import com.zenyard.ghidra.api.generated.model.UnlimitedUsage;
import com.zenyard.ghidra.api.generated.model.UsageResponse;
import com.zenyard.ghidra.ui.UsageBlockedDialog;

public final class UsageState {
    public static final String BLOCKED_DIALOG_TITLE = "Usage Limit Reached";
    public static final String CONTACT_EMAIL = "access@zenyard.ai";
    static final double NEAR_CAPACITY_THRESHOLD = 0.8;

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

    /**
     * Build a UsageState from an HTTP error status code and raw JSON body.
     * <ul>
     *   <li>402 → {@link Kind#LIMITED} with parsed {@code usage_percentage} (divided by 100),
     *       falls back to 1.0 when the body cannot be parsed.</li>
     *   <li>404 → {@link Kind#EXPIRED}.</li>
     *   <li>Anything else → {@link Kind#UNKNOWN}.</li>
     * </ul>
     */
    public static UsageState fromApiError(int statusCode, String body) {
        if (statusCode == 402) {
            double percentage = 1.0;
            try {
                if (body != null && !body.isEmpty()) {
                    JsonObject root = JsonParser.parseString(body).getAsJsonObject();
                    Double parsed = extractUsagePercentage(root);
                    if (parsed != null) {
                        percentage = parsed / 100.0;
                    }
                }
            } catch (Exception e) {
                // fall through with default 1.0
            }
            return new UsageState(Kind.LIMITED, percentage, null);
        }
        if (statusCode == 404) {
            return new UsageState(Kind.EXPIRED, null, null);
        }
        return UsageState.unknown();
    }

    private static Double extractUsagePercentage(JsonObject obj) {
        if (obj.has("usage_percentage")) {
            return obj.get("usage_percentage").getAsDouble();
        }
        if (obj.has("detail")) {
            JsonElement detail = obj.get("detail");
            if (detail.isJsonObject() && detail.getAsJsonObject().has("usage_percentage")) {
                return detail.getAsJsonObject().get("usage_percentage").getAsDouble();
            }
        }
        return null;
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
        return kind == Kind.EXPIRED || kind == Kind.UNLIMITED;
    }

    public UsageLevel getDisplayLevel() {
        if (kind == Kind.EXPIRED) {
            return UsageLevel.EXPIRED;
        }
        if (kind == Kind.LIMITED && usagePercentage != null) {
            if (usagePercentage >= 1.0) {
                return UsageLevel.OVER_LIMIT;
            }
            if (usagePercentage >= NEAR_CAPACITY_THRESHOLD) {
                return UsageLevel.WARNING;
            }
        }
        return UsageLevel.NORMAL;
    }

    public String getDisplayTextForStatusBar() {
        if (!isVisible()) {
            return "";
        }
        if (kind == Kind.EXPIRED) {
            return "EXPIRED";
        }
        if (kind == Kind.UNLIMITED) {
            return "Usage: Unlimited";
        }
        if (kind == Kind.LIMITED && usagePercentage != null) {
            return "Usage " + formatUsagePercent();
        }
        return "";
    }

    /**
     * Backward-compatible alias for older callers/tests.
     */
    public String getDisplayText() {
        return getDisplayTextForStatusBar();
    }

    public String getDisplayTextForDialog() {
        if (!isVisible()) {
            return "";
        }
        if (kind == Kind.EXPIRED) {
            return "EXPIRED";
        }
        if (kind == Kind.UNLIMITED) {
            return "Unlimited";
        }
        if (kind == Kind.LIMITED && usagePercentage != null) {
            return formatUsagePercent();
        }
        return "";
    }

    private String formatUsagePercent() {
        int percent = (int) Math.round(usagePercentage * 100.0);
        if (percent < 0) {
            percent = 0;
        }
        if (percent > 100) {
            percent = 100;
        }
        return percent + "%";
    }

    public String getTooltip() {
        if (kind == Kind.EXPIRED) {
            return "Your plan has expired. Upgrade to continue. " + getContactSupportText();
        }
        if (kind == Kind.LIMITED && usagePercentage != null) {
            if (usagePercentage >= 1.0) {
                return "Quota reached. Want to keep going? Contact us";
            }
            return "Have questions or want more quota? Contact us";
        }
        return "";
    }

    public boolean shouldOpenContactEmail() {
        return kind == Kind.LIMITED && usagePercentage != null && usagePercentage >= 1.0;
    }

    public boolean isBlocked() {
        return kind == Kind.EXPIRED || (kind == Kind.LIMITED && usagePercentage != null && usagePercentage >= 1.0);
    }

    public String getBlockedMessage() {
        String tooltip = getTooltip();
        return tooltip.isEmpty() ? "Usage limit reached. Upgrade to continue. " + getContactSupportText() : tooltip;
    }

    public static String getContactSupportText() {
        return "Contact us: " + CONTACT_EMAIL;
    }

    public static void showBlockedDialog(Component parent, UsageState state) {
        UsageState resolved = state != null ? state : UsageState.unknown();
        UsageBlockedDialog.showDialog(parent, resolved);
    }

    public static boolean isContactEmailSupported() {
        if (!Desktop.isDesktopSupported()) {
            return false;
        }
        try {
            Desktop desktop = Desktop.getDesktop();
            return desktop.isSupported(Desktop.Action.MAIL) || desktop.isSupported(Desktop.Action.BROWSE);
        } catch (Exception ignored) {
            return false;
        }
    }

    public static void openContactEmail() {
        if (!isContactEmailSupported()) {
            return;
        }
        try {
            URI emailUri = new URI("mailto:" + CONTACT_EMAIL);
            Desktop desktop = Desktop.getDesktop();
            if (desktop.isSupported(Desktop.Action.MAIL)) {
                desktop.mail(emailUri);
            }
            else if (desktop.isSupported(Desktop.Action.BROWSE)) {
                desktop.browse(emailUri);
            }
        }
        catch (Exception ignored) {
            // Best-effort link behavior only.
        }
    }

    public String getPlanLabel() {
        switch (kind) {
            case UNLIMITED:
                return "Unlimited";
            case LIMITED:
                return "Free Trial";
            case EXPIRED:
                return "Expired";
            default:
                return "Unknown";
        }
    }
}
