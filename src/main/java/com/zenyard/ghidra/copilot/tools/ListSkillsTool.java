package com.zenyard.ghidra.copilot.tools;

import java.util.List;

import com.zenyard.ghidra.copilot.skills.SkillMetadata;
import com.zenyard.ghidra.copilot.skills.SkillsService;

import dev.langchain4j.agent.tool.Tool;

/**
 * Lists discovered skills metadata.
 */
public class ListSkillsTool {

    private final SkillsService skillsService;

    public ListSkillsTool(SkillsService skillsService) {
        this.skillsService = skillsService;
    }

    @Tool(
        name = "list_skills",
        value = "List all discovered skills with name, description, and path."
    )
    public String listSkills() {
        if (skillsService == null) {
            return "Skills are not configured for this session.";
        }
        skillsService.refresh();
        List<SkillMetadata> skills = skillsService.listSkills();
        if (skills.isEmpty()) {
            return "No skills found in configured sources.";
        }
        StringBuilder out = new StringBuilder();
        for (SkillMetadata skill : skills) {
            if (out.length() > 0) {
                out.append('\n');
            }
            out.append("- ")
                .append(skill.getName())
                .append(": ")
                .append(skill.getDescription())
                .append(" (")
                .append(skill.getPath())
                .append(")");
        }
        return out.toString();
    }
}
