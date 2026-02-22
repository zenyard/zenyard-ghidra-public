package com.zenyard.ghidra.copilot.skills;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.zenyard.ghidra.copilot.CopilotConfig;

/**
 * Resolves skills source directories from Copilot additional params.
 */
public final class SkillsSourceResolver {

    private SkillsSourceResolver() {
    }

    public static List<String> resolve(CopilotConfig config) {
        if (config == null || config.getAdditionalParams() == null) {
            return List.of();
        }
        Map<String, Object> params = config.getAdditionalParams();
        Object value = firstNonNull(
            params.get("skills_sources"),
            params.get("skillsSources"),
            params.get("skill_sources")
        );
        if (value == null) {
            return List.of();
        }

        Set<String> normalized = new LinkedHashSet<>();
        if (value instanceof List<?> list) {
            for (Object item : list) {
                addSource(normalized, item);
            }
        } else {
            String raw = String.valueOf(value);
            for (String token : raw.split(",")) {
                addSource(normalized, token);
            }
        }
        return new ArrayList<>(normalized);
    }

    private static Object firstNonNull(Object... values) {
        for (Object value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static void addSource(Set<String> target, Object value) {
        if (value == null) {
            return;
        }
        String raw = String.valueOf(value).trim();
        if (raw.isEmpty()) {
            return;
        }
        Path normalized = Paths.get(raw).normalize();
        target.add(normalized.toString());
    }
}
