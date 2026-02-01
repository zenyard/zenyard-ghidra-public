package com.zenyard.ghidra.copilot;

import com.zenyard.ghidra.api.generated.model.UserConfig;
import java.util.Collections;
import java.util.Map;

/**
 * Maps API UserConfig to CopilotConfig.
 */
public final class CopilotConfigMapper {

    private CopilotConfigMapper() {
    }

    public static CopilotConfig fromUserConfig(UserConfig userConfig) {
        if (userConfig == null || userConfig.getCopilot() == null) {
            return null;
        }
        com.zenyard.ghidra.api.generated.model.CopilotConfig apiConfig =
            userConfig.getCopilot();
        if (apiConfig == null) {
            return null;
        }
        Map<String, Object> additionalParams = Collections.emptyMap();
        Object rawParams = apiConfig.getAdditionalParams();
        if (rawParams instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> castParams = (Map<String, Object>) rawParams;
            additionalParams = castParams;
        }
        return new CopilotConfig(
            apiConfig.getModelName(),
            apiConfig.getModelProvider(),
            additionalParams
        );
    }
}
