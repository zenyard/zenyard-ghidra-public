package com.zenyard.ghidra.util;

import java.lang.reflect.Method;
import java.util.concurrent.CompletableFuture;

import com.zenyard.ghidra.api.generated.ApiException;
import com.zenyard.ghidra.api.generated.api.UserApi;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;

import ghidra.program.model.listing.Program;

/**
 * Shared binary-size gate used to decide whether background tasks may start.
 */
public final class BinarySizeLimitGate {
    public static final String PROP_BINARY_SIZE_LIMIT_EXCEEDED = "binary_size_limit_exceeded";
    public static final String PROP_BINARY_SIZE_LIMIT_MB = "binary_size_limit_mb";

    private static final String[] MAX_SIZE_GETTERS = {
        "getMaxBinarySizeMb",
        "getMaxBinarySizeMB"
    };

    private BinarySizeLimitGate() {
    }

    public enum CheckStatus {
        PASSED,
        BLOCKED,
        NOT_VERIFIED
    }

    public static final class CheckResult {
        private final CheckStatus status;
        private final Integer maxBinarySizeMb;
        private final String message;

        private CheckResult(CheckStatus status, Integer maxBinarySizeMb, String message) {
            this.status = status;
            this.maxBinarySizeMb = maxBinarySizeMb;
            this.message = message;
        }

        public CheckStatus getStatus() {
            return status;
        }

        public Integer getMaxBinarySizeMb() {
            return maxBinarySizeMb;
        }

        public String getMessage() {
            return message;
        }

        public boolean isPassed() {
            return status == CheckStatus.PASSED;
        }

        public boolean isBlocked() {
            return status == CheckStatus.BLOCKED;
        }
    }

    public static CheckResult check(Program program, UserApi userApi) {
        if (program == null || program.isClosed()) {
            return new CheckResult(CheckStatus.NOT_VERIFIED, null, "No active program");
        }
        if (userApi == null) {
            return new CheckResult(CheckStatus.NOT_VERIFIED, null, "User API unavailable");
        }

        Integer maxBinarySizeMb;
        try {
            maxBinarySizeMb = fetchMaxBinarySizeMb(userApi);
        } catch (Exception e) {
            return new CheckResult(CheckStatus.NOT_VERIFIED, null,
                "Failed to fetch user config: " + e.getMessage());
        }
        if (maxBinarySizeMb == null || maxBinarySizeMb <= 0) {
            return new CheckResult(CheckStatus.NOT_VERIFIED, null,
                "User config does not expose max_binary_size_mb");
        }

        long binarySizeBytes;
        try {
            binarySizeBytes = BinarySerializer.getInputFileSizeBytes(program);
        } catch (Exception e) {
            return new CheckResult(CheckStatus.NOT_VERIFIED, maxBinarySizeMb,
                "Failed to determine binary size: " + e.getMessage());
        }

        long maxAllowedBytes = maxBinarySizeMb * 1024L * 1024L;
        if (binarySizeBytes > maxAllowedBytes) {
            return new CheckResult(CheckStatus.BLOCKED, maxBinarySizeMb, "Binary exceeds maximum size");
        }
        return new CheckResult(CheckStatus.PASSED, maxBinarySizeMb, "Binary size check passed");
    }

    public static void persistResult(Program program, CheckResult result) {
        if (program == null || result == null) {
            return;
        }
        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        props.setString(PROP_BINARY_SIZE_LIMIT_EXCEEDED, result.isBlocked() ? "true" : "false");
        if (result.getMaxBinarySizeMb() != null && result.getMaxBinarySizeMb() > 0) {
            props.setInt(PROP_BINARY_SIZE_LIMIT_MB, result.getMaxBinarySizeMb());
        }
    }

    private static Integer fetchMaxBinarySizeMb(UserApi userApi) throws Exception {
        Object userConfig = CompletableFuture.supplyAsync(() -> {
            try {
                return userApi.getUserConfig();
            } catch (ApiException e) {
                throw new RuntimeException(e);
            }
        }).get();
        return extractMaxBinarySizeMb(userConfig);
    }

    private static Integer extractMaxBinarySizeMb(Object userConfig) {
        if (userConfig == null) {
            return null;
        }
        for (String getterName : MAX_SIZE_GETTERS) {
            try {
                Method getter = userConfig.getClass().getMethod(getterName);
                Object value = getter.invoke(userConfig);
                Integer parsed = toPositiveInteger(value);
                if (parsed != null) {
                    return parsed;
                }
            } catch (ReflectiveOperationException ignored) {
                // Try alternate accessor names.
            }
        }
        return null;
    }

    private static Integer toPositiveInteger(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number) {
            int parsed = ((Number) value).intValue();
            return parsed > 0 ? parsed : null;
        }
        if (value instanceof String) {
            try {
                int parsed = Integer.parseInt(((String) value).trim());
                return parsed > 0 ? parsed : null;
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }
}
