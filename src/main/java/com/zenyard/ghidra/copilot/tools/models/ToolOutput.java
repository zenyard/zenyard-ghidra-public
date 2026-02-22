package com.zenyard.ghidra.copilot.tools.models;

/**
 * Standardized tool output for large results stored in artifacts.
 */
public class ToolOutput {
    private final String summary;
    private final String artifactPath;
    private final Integer itemCount;
    private final String content;

    public ToolOutput(String summary, String artifactPath, Integer itemCount) {
        this(summary, artifactPath, itemCount, null);
    }

    public ToolOutput(String summary, String artifactPath, Integer itemCount, String content) {
        this.summary = summary;
        this.artifactPath = artifactPath;
        this.itemCount = itemCount;
        this.content = content;
    }

    public String getSummary() {
        return summary;
    }

    public String getArtifactPath() {
        return artifactPath;
    }

    public Integer getItemCount() {
        return itemCount;
    }

    public String getContent() {
        return content;
    }
}
