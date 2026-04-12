package com.zenyard.ghidra.copilot.skills;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SkillsRegistryLoaderTest {

    @TempDir
    private Path tempDir;

    @Test
    void loadLastSourceWinsForDuplicateNames() throws IOException {
        Path source1 = tempDir.resolve("source1");
        Path source2 = tempDir.resolve("source2");
        Files.createDirectories(source1.resolve("reverse-workflow"));
        Files.createDirectories(source2.resolve("reverse-workflow"));

        Files.writeString(source1.resolve("reverse-workflow").resolve("SKILL.md"), """
            ---
            name: reverse-workflow
            description: first-source
            ---
            # Instructions
            """);
        Files.writeString(source2.resolve("reverse-workflow").resolve("SKILL.md"), """
            ---
            name: reverse-workflow
            description: second-source
            ---
            # Instructions
            """);

        SkillsRegistryLoader loader = new SkillsRegistryLoader(
            List.of(source1.toString(), source2.toString())
        );
        SkillsRegistryLoader.SkillsLoadResult result = loader.load();

        assertEquals(1, result.getSkills().size());
        assertEquals("second-source", result.getSkills().get(0).getDescription());
    }

    @Test
    void loadMissingSkillFileIsIgnored() throws IOException {
        Path source = tempDir.resolve("source");
        Files.createDirectories(source.resolve("has-skill"));
        Files.createDirectories(source.resolve("no-skill"));

        Files.writeString(source.resolve("has-skill").resolve("SKILL.md"), """
            ---
            name: has-skill
            description: available
            ---
            # Instructions
            """);

        SkillsRegistryLoader loader = new SkillsRegistryLoader(List.of(source.toString()));
        SkillsRegistryLoader.SkillsLoadResult result = loader.load();

        assertEquals(1, result.getSkills().size());
        assertTrue(result.getSkills().get(0).getPath().endsWith("SKILL.md"));
        assertFalse(result.getSkills().get(0).getDescription().isBlank());
    }
}
