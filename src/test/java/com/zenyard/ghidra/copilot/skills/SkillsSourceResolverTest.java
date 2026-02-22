package com.zenyard.ghidra.copilot.skills;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.copilot.CopilotConfig;

class SkillsSourceResolverTest {

    @Test
    void resolve_listParam_returnsAllSources() {
        CopilotConfig config = new CopilotConfig(
            "gpt",
            "openai",
            Map.of("skills_sources", List.of("/skills/user", "/skills/project"))
        );

        List<String> sources = SkillsSourceResolver.resolve(config);
        assertEquals(2, sources.size());
        assertEquals("/skills/user", sources.get(0));
        assertEquals("/skills/project", sources.get(1));
    }

    @Test
    void resolve_csvParam_parsesAndNormalizes() {
        CopilotConfig config = new CopilotConfig(
            "gpt",
            "openai",
            Map.of("skillsSources", " /a/b , /c/d ")
        );

        List<String> sources = SkillsSourceResolver.resolve(config);
        assertEquals(2, sources.size());
        assertTrue(sources.contains("/a/b"));
        assertTrue(sources.contains("/c/d"));
    }
}
