package com.zenyard.ghidra.copilot.skills;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Runtime skills service with refresh and secure read operations.
 */
public final class SkillsService {

    private final List<String> sourcePaths;
    private final SkillsRegistryLoader loader;
    private SkillsRegistryLoader.SkillsLoadResult cache;
    private Map<String, SkillMetadata> byName;

    public SkillsService(List<String> sourcePaths) {
        this.sourcePaths = sourcePaths == null ? List.of() : List.copyOf(sourcePaths);
        this.loader = new SkillsRegistryLoader(this.sourcePaths);
        this.cache = new SkillsRegistryLoader.SkillsLoadResult(this.sourcePaths, List.of());
        this.byName = new LinkedHashMap<>();
    }

    public synchronized SkillsRegistryLoader.SkillsLoadResult refresh() {
        cache = loader.load();
        Map<String, SkillMetadata> nextByName = new LinkedHashMap<>();
        for (SkillMetadata skill : cache.getSkills()) {
            nextByName.put(skill.getName(), skill);
        }
        byName = nextByName;
        return cache;
    }

    public synchronized List<SkillMetadata> listSkills() {
        return cache.getSkills();
    }

    public synchronized List<String> getSourcePaths() {
        return cache.getSourcePaths();
    }

    public synchronized Optional<SkillMetadata> findByName(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(byName.get(name.trim()));
    }

    public synchronized Optional<SkillMetadata> findByPath(String path) {
        if (path == null || path.isBlank()) {
            return Optional.empty();
        }
        String normalized = normalize(path);
        for (SkillMetadata skill : byName.values()) {
            if (normalize(skill.getPath()).equals(normalized)) {
                return Optional.of(skill);
            }
        }
        return Optional.empty();
    }

    public synchronized Optional<String> readSkillContent(String nameOrPath) {
        if (nameOrPath == null || nameOrPath.isBlank()) {
            return Optional.empty();
        }
        Optional<SkillMetadata> match = findByName(nameOrPath.trim());
        if (match.isEmpty()) {
            match = findByPath(nameOrPath.trim());
        }
        if (match.isEmpty()) {
            return Optional.empty();
        }
        Path path = Paths.get(match.get().getPath()).normalize().toAbsolutePath();
        if (!isWithinAllowedSources(path)) {
            return Optional.empty();
        }
        try {
            return Optional.of(Files.readString(path, StandardCharsets.UTF_8));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    public synchronized List<Map<String, Object>> toStateSkillMetadata() {
        List<Map<String, Object>> serialized = new ArrayList<>();
        for (SkillMetadata skill : cache.getSkills()) {
            Map<String, Object> row = new HashMap<>();
            row.put("name", skill.getName());
            row.put("description", skill.getDescription());
            row.put("path", skill.getPath());
            row.put("metadata", skill.getMetadata());
            row.put("license", skill.getLicense());
            row.put("compatibility", skill.getCompatibility());
            row.put("allowedTools", skill.getAllowedTools());
            serialized.add(row);
        }
        return serialized;
    }

    private boolean isWithinAllowedSources(Path path) {
        for (String source : sourcePaths) {
            Path sourcePath = Paths.get(source).normalize().toAbsolutePath();
            if (path.startsWith(sourcePath)) {
                return true;
            }
        }
        return false;
    }

    private static String normalize(String input) {
        return Paths.get(input).normalize().toAbsolutePath().toString();
    }
}
