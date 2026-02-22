package com.zenyard.ghidra.copilot.skills;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;

import org.junit.jupiter.api.Test;

class SkillFrontmatterParserTest {

    @Test
    void parse_validFrontmatter_returnsMetadata() {
        String content = """
            ---
            name: reverse-workflow
            description: Structured reverse engineering process
            allowed-tools:
              - list_functions
              - decompile_function
            metadata:
              owner: team-re
            license: MIT
            compatibility: ghidra-11
            ---
            # Instructions
            """;

        Optional<SkillMetadata> parsed = SkillFrontmatterParser.parse(
            content,
            "/skills/reverse-workflow/SKILL.md",
            "reverse-workflow"
        );

        assertTrue(parsed.isPresent());
        SkillMetadata skill = parsed.get();
        assertEquals("reverse-workflow", skill.getName());
        assertEquals("Structured reverse engineering process", skill.getDescription());
        assertEquals(2, skill.getAllowedTools().size());
        assertEquals("team-re", skill.getMetadata().get("owner"));
        assertEquals("MIT", skill.getLicense());
        assertEquals("ghidra-11", skill.getCompatibility());
    }

    @Test
    void parse_missingFrontmatter_returnsEmpty() {
        Optional<SkillMetadata> parsed = SkillFrontmatterParser.parse(
            "# no frontmatter",
            "/skills/invalid/SKILL.md",
            "invalid"
        );
        assertFalse(parsed.isPresent());
    }

    @Test
    void parse_longDescription_isTruncated() {
        String longDescription = "a".repeat(1200);
        String content = """
            ---
            name: reverse-workflow
            description: %s
            ---
            # Instructions
            """.formatted(longDescription);

        Optional<SkillMetadata> parsed = SkillFrontmatterParser.parse(
            content,
            "/skills/reverse-workflow/SKILL.md",
            "reverse-workflow"
        );

        assertTrue(parsed.isPresent());
        assertEquals(
            SkillFrontmatterParser.MAX_SKILL_DESCRIPTION_LENGTH,
            parsed.get().getDescription().length()
        );
    }
}
