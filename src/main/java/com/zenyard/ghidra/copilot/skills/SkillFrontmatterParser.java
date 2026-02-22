package com.zenyard.ghidra.copilot.skills;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.yaml.snakeyaml.Yaml;

/**
 * Parser for SKILL.md YAML frontmatter blocks.
 */
public final class SkillFrontmatterParser {

    public static final int MAX_SKILL_FILE_SIZE = 10 * 1024 * 1024;
    public static final int MAX_SKILL_NAME_LENGTH = 64;
    public static final int MAX_SKILL_DESCRIPTION_LENGTH = 1024;
    public static final int MAX_SKILL_COMPATIBILITY_LENGTH = 256;

    private static final Logger LOG = Logger.getLogger(SkillFrontmatterParser.class.getName());
    private static final Pattern FRONTMATTER_PATTERN =
        Pattern.compile("^---\\s*\\R(.*?)\\R---\\s*\\R", Pattern.DOTALL);

    private SkillFrontmatterParser() {
    }

    public static Optional<SkillMetadata> parse(
            String content,
            String skillPath,
            String directoryName) {
        if (content == null || content.isBlank()) {
            return Optional.empty();
        }
        if (content.length() > MAX_SKILL_FILE_SIZE) {
            LOG.warning(() -> "Skipping " + skillPath + ": content exceeds max size");
            return Optional.empty();
        }

        Matcher matcher = FRONTMATTER_PATTERN.matcher(content);
        if (!matcher.find()) {
            LOG.warning(() -> "Skipping " + skillPath + ": no YAML frontmatter");
            return Optional.empty();
        }

        Object loaded;
        try {
            loaded = new Yaml().load(matcher.group(1));
        } catch (RuntimeException e) {
            LOG.warning(() -> "Invalid YAML in " + skillPath + ": " + e.getMessage());
            return Optional.empty();
        }
        if (!(loaded instanceof Map<?, ?> map)) {
            LOG.warning(() -> "Skipping " + skillPath + ": frontmatter is not a map");
            return Optional.empty();
        }

        String name = asTrimmed(map.get("name"));
        String description = asTrimmed(map.get("description"));
        if (name.isEmpty() || description.isEmpty()) {
            LOG.warning(() -> "Skipping " + skillPath + ": missing name or description");
            return Optional.empty();
        }

        String safeName = truncate(name, MAX_SKILL_NAME_LENGTH);
        String safeDescription = truncate(description, MAX_SKILL_DESCRIPTION_LENGTH);
        NameValidation validation = validateSkillName(safeName, directoryName);
        if (!validation.valid) {
            LOG.warning(() -> "Skill name warning for " + skillPath + ": " + validation.error);
        }

        String license = emptyToNull(asTrimmed(map.get("license")));
        String compatibility = emptyToNull(asTrimmed(map.get("compatibility")));
        if (compatibility != null && compatibility.length() > MAX_SKILL_COMPATIBILITY_LENGTH) {
            compatibility = compatibility.substring(0, MAX_SKILL_COMPATIBILITY_LENGTH);
        }

        List<String> allowedTools = parseAllowedTools(map.get("allowed-tools"));
        Map<String, String> metadata = parseMetadata(map.get("metadata"));

        SkillMetadata result = new SkillMetadata(
            safeName,
            safeDescription,
            skillPath,
            metadata,
            license,
            compatibility,
            allowedTools
        );
        return Optional.of(result);
    }

    private static List<String> parseAllowedTools(Object raw) {
        if (raw == null) {
            return List.of();
        }
        List<String> tools = new ArrayList<>();
        if (raw instanceof List<?> list) {
            for (Object item : list) {
                String value = asTrimmed(item);
                if (!value.isEmpty()) {
                    tools.add(value);
                }
            }
            return tools;
        }
        String single = asTrimmed(raw);
        if (single.isEmpty()) {
            return List.of();
        }
        for (String value : single.split("\\s+")) {
            String trimmed = value.trim();
            if (!trimmed.isEmpty()) {
                tools.add(trimmed);
            }
        }
        return tools;
    }

    private static Map<String, String> parseMetadata(Object raw) {
        if (!(raw instanceof Map<?, ?> map)) {
            return Map.of();
        }
        Map<String, String> output = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            output.put(String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
        }
        return output;
    }

    private static String asTrimmed(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private static String truncate(String input, int maxLength) {
        if (input == null) {
            return "";
        }
        return input.length() <= maxLength ? input : input.substring(0, maxLength);
    }

    private static String emptyToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static NameValidation validateSkillName(String name, String directoryName) {
        if (name.isEmpty()) {
            return new NameValidation(false, "name is required");
        }
        if (name.length() > MAX_SKILL_NAME_LENGTH) {
            return new NameValidation(false, "name exceeds max length");
        }
        if (name.startsWith("-") || name.endsWith("-") || name.contains("--")) {
            return new NameValidation(false, "name must use lowercase alphanumeric and single hyphens");
        }
        String lowered = name.toLowerCase(Locale.ROOT);
        if (!name.equals(lowered)) {
            return new NameValidation(false, "name should be lowercase");
        }
        for (char c : name.toCharArray()) {
            if (c == '-') {
                continue;
            }
            if (!Character.isLowerCase(c) && !Character.isDigit(c)) {
                return new NameValidation(false, "name must use lowercase alphanumeric and single hyphens");
            }
        }
        if (directoryName != null && !directoryName.isBlank() && !name.equals(directoryName)) {
            return new NameValidation(
                false,
                "name '" + name + "' should match directory '" + directoryName + "'"
            );
        }
        return new NameValidation(true, "");
    }

    private static final class NameValidation {
        private final boolean valid;
        private final String error;

        private NameValidation(boolean valid, String error) {
            this.valid = valid;
            this.error = error;
        }
    }
}
