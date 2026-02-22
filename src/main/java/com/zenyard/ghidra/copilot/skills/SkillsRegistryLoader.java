package com.zenyard.ghidra.copilot.skills;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Loads skills from configured source directories.
 */
public final class SkillsRegistryLoader {

    private static final Logger LOG = Logger.getLogger(SkillsRegistryLoader.class.getName());

    private final List<String> sourcePaths;

    public SkillsRegistryLoader(List<String> sourcePaths) {
        this.sourcePaths = sourcePaths == null ? List.of() : List.copyOf(sourcePaths);
    }

    public SkillsLoadResult load() {
        Map<String, SkillMetadata> byName = new LinkedHashMap<>();
        for (String sourcePath : sourcePaths) {
            Path source = Paths.get(sourcePath);
            if (!Files.isDirectory(source)) {
                continue;
            }
            List<Path> skillDirs = listDirectories(source);
            for (Path skillDir : skillDirs) {
                Path skillFile = skillDir.resolve("SKILL.md");
                if (!Files.isRegularFile(skillFile)) {
                    continue;
                }
                String content;
                try {
                    content = Files.readString(skillFile, StandardCharsets.UTF_8);
                } catch (IOException e) {
                    LOG.warning(() -> "Failed reading " + skillFile + ": " + e.getMessage());
                    continue;
                }

                Optional<SkillMetadata> parsed = SkillFrontmatterParser.parse(
                    content,
                    skillFile.toAbsolutePath().normalize().toString(),
                    skillDir.getFileName() == null ? "" : skillDir.getFileName().toString()
                );
                parsed.ifPresent(skill -> {
                    // Last source wins for duplicate skill names.
                    byName.put(skill.getName(), skill);
                });
            }
        }
        return new SkillsLoadResult(sourcePaths, new ArrayList<>(byName.values()));
    }

    private List<Path> listDirectories(Path source) {
        try (var stream = Files.list(source)) {
            return stream
                .filter(Files::isDirectory)
                .toList();
        } catch (IOException e) {
            LOG.warning(() -> "Failed listing " + source + ": " + e.getMessage());
            return List.of();
        }
    }

    /**
     * Loaded skills plus configured sources.
     */
    public static final class SkillsLoadResult {
        private final List<String> sourcePaths;
        private final List<SkillMetadata> skills;

        public SkillsLoadResult(List<String> sourcePaths, List<SkillMetadata> skills) {
            this.sourcePaths = sourcePaths == null ? List.of() : List.copyOf(sourcePaths);
            this.skills = skills == null ? List.of() : List.copyOf(skills);
        }

        public List<String> getSourcePaths() {
            return sourcePaths;
        }

        public List<SkillMetadata> getSkills() {
            return skills;
        }
    }
}
