package com.zenyard.ghidra.copilot.tools;

import java.util.Optional;

import com.zenyard.ghidra.copilot.skills.SkillsService;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;

/**
 * Reads full SKILL.md contents for a discovered skill.
 */
public class ReadSkillTool {

    private final SkillsService skillsService;

    public ReadSkillTool(SkillsService skillsService) {
        this.skillsService = skillsService;
    }

    @Tool(
        name = "read_skill",
        value = """
            Read the full SKILL.md instructions for a discovered skill.
            Input should be either the skill name or the absolute skill path shown in prompt metadata.
            """
    )
    public String readSkill(
            @P("Skill identifier. Use either a discovered skill name or its absolute SKILL.md path.") String skillNameOrPath) {
        if (skillsService == null) {
            return "Skills are not configured for this session.";
        }
        skillsService.refresh();
        Optional<String> content = skillsService.readSkillContent(skillNameOrPath);
        if (content.isEmpty()) {
            return "Skill not found or not readable: " + skillNameOrPath;
        }
        return content.get();
    }
}
