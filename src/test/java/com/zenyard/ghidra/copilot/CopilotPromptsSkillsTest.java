package com.zenyard.ghidra.copilot;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.copilot.skills.SkillMetadata;

class CopilotPromptsSkillsTest {

    @Test
    void renderSkillsPrompt_includesLocationsAndSkills() {
        SkillMetadata skill = new SkillMetadata(
            "reverse-workflow",
            "Structured reverse engineering process",
            "/skills/reverse-workflow/SKILL.md",
            Map.of("owner", "team-re"),
            "MIT",
            "ghidra-11",
            List.of("list_functions", "decompile_function")
        );

        String prompt = CopilotPrompts.renderSkillsPrompt(
            List.of("/skills/user", "/skills/project"),
            List.of(skill)
        );

        assertTrue(prompt.contains("/skills/user"));
        assertTrue(prompt.contains("/skills/project"));
        assertTrue(prompt.contains("reverse-workflow"));
        assertTrue(prompt.contains("Read `/skills/reverse-workflow/SKILL.md`"));
        assertTrue(prompt.contains("Allowed tools: list_functions, decompile_function"));
    }
}
