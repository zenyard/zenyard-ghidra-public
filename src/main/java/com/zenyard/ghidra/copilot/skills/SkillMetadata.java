package com.zenyard.ghidra.copilot.skills;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Metadata extracted from a SKILL.md frontmatter block.
 */
public final class SkillMetadata {

    private final String name;
    private final String description;
    private final String path;
    private final Map<String, String> metadata;
    private final String license;
    private final String compatibility;
    private final List<String> allowedTools;

    public SkillMetadata(
            String name,
            String description,
            String path,
            Map<String, String> metadata,
            String license,
            String compatibility,
            List<String> allowedTools) {
        this.name = Objects.requireNonNull(name, "name");
        this.description = Objects.requireNonNull(description, "description");
        this.path = Objects.requireNonNull(path, "path");
        this.metadata = metadata == null ? Map.of() : Collections.unmodifiableMap(metadata);
        this.license = license;
        this.compatibility = compatibility;
        this.allowedTools = allowedTools == null ? List.of() : List.copyOf(allowedTools);
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getPath() {
        return path;
    }

    public Map<String, String> getMetadata() {
        return metadata;
    }

    public String getLicense() {
        return license;
    }

    public String getCompatibility() {
        return compatibility;
    }

    public List<String> getAllowedTools() {
        return allowedTools;
    }
}
