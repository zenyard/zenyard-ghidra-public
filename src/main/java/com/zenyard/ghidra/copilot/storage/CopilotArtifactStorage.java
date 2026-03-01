package com.zenyard.ghidra.copilot.storage;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.framework.model.DomainFile;

/**
 * Simple filesystem-backed storage for Copilot deep-agent artifacts.
 */
public class CopilotArtifactStorage {

    private final Path baseDir;

    public CopilotArtifactStorage(Program program) {
        this.baseDir = resolveBaseDir(program);
    }

    /**
     * Return the base directory used for artifact storage, or {@code null} if
     * it could not be resolved.  Used by the Python sandbox to restrict
     * filesystem access to this path.
     */
    public Path getBaseDir() {
        return baseDir;
    }

    public Map<String, String> loadArtifacts() {
        Map<String, String> artifacts = new HashMap<>();
        if (baseDir == null || !Files.exists(baseDir)) {
            return artifacts;
        }
        try {
            Files.walk(baseDir)
                .filter(Files::isRegularFile)
                .forEach(path -> {
                    String key = baseDir.relativize(path).toString();
                    try {
                        String content = Files.readString(path, StandardCharsets.UTF_8);
                        artifacts.put(key, content);
                    } catch (IOException e) {
                        Msg.debug(this, "Failed to read artifact: " + path + " (" + e.getMessage() + ")");
                    }
                });
        } catch (IOException e) {
            Msg.debug(this, "Failed to load artifacts: " + e.getMessage());
        }
        return artifacts;
    }

    public void writeArtifacts(Map<String, String> artifacts) {
        if (baseDir == null || artifacts == null || artifacts.isEmpty()) {
            return;
        }
        artifacts.forEach((key, value) -> {
            Path path = resolveArtifactPath(key);
            if (path == null) {
                return;
            }
            try {
                Files.createDirectories(path.getParent());
                Files.writeString(path, value != null ? value : "", StandardCharsets.UTF_8);
            } catch (IOException e) {
                Msg.debug(this, "Failed to write artifact: " + path + " (" + e.getMessage() + ")");
            }
        });
    }

    private static final String SESSION_SUMMARY_KEY = "notes/session_summary.md";
    private static final int SESSION_SUMMARY_MAX_CHARS = 6000;
    private static final DateTimeFormatter TIMESTAMP_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    /**
     * Load the persisted session summary for the current program.
     * Returns empty string if no summary exists yet.
     */
    public String loadSessionSummary() {
        Path path = resolveArtifactPath(SESSION_SUMMARY_KEY);
        if (path == null || !Files.exists(path)) {
            return "";
        }
        try {
            String content = Files.readString(path, StandardCharsets.UTF_8);
            // Return the tail portion to stay within context budget
            if (content.length() > SESSION_SUMMARY_MAX_CHARS) {
                int cutAt = content.length() - SESSION_SUMMARY_MAX_CHARS;
                int newline = content.indexOf('\n', cutAt);
                content = (newline > 0 ? content.substring(newline + 1) : content.substring(cutAt));
            }
            return content;
        } catch (IOException e) {
            Msg.debug(this, "Failed to load session summary: " + e.getMessage());
            return "";
        }
    }

    /**
     * Append a timestamped entry to the session summary for the current program.
     * Each entry records the query, completed work, and a response snippet so future
     * sessions know what has already been explored.
     */
    public void appendSessionEntry(String userQuery, java.util.List<String> completedTodos, String responseSnippet) {
        Path path = resolveArtifactPath(SESSION_SUMMARY_KEY);
        if (path == null) {
            return;
        }
        try {
            Files.createDirectories(path.getParent());
            StringBuilder entry = new StringBuilder();
            entry.append("\n--- ").append(TIMESTAMP_FMT.format(Instant.now())).append(" ---\n");
            if (userQuery != null && !userQuery.isBlank()) {
                String q = userQuery.length() > 200 ? userQuery.substring(0, 200) + "..." : userQuery;
                entry.append("Query: ").append(q).append("\n");
            }
            if (completedTodos != null && !completedTodos.isEmpty()) {
                entry.append("Completed:\n");
                for (String todo : completedTodos) {
                    entry.append("  - ").append(todo).append("\n");
                }
            }
            if (responseSnippet != null && !responseSnippet.isBlank()) {
                String snippet = responseSnippet.length() > 500
                    ? responseSnippet.substring(0, 500) + "..." : responseSnippet;
                entry.append("Summary: ").append(snippet).append("\n");
            }
            Files.writeString(path, entry.toString(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            Msg.debug(this, "Failed to append session entry: " + e.getMessage());
        }
    }

    private Path resolveArtifactPath(String key) {
        if (key == null || key.isBlank()) {
            return null;
        }
        String sanitized = key.replace("\\\\", "/");
        while (sanitized.startsWith("/")) {
            sanitized = sanitized.substring(1);
        }
        if (sanitized.contains("..")) {
            return null;
        }
        return baseDir.resolve(Paths.get(sanitized)).normalize();
    }

    private Path resolveBaseDir(Program program) {
        try {
            DomainFile domainFile = program.getDomainFile();
            if (domainFile != null) {
                String pathname = domainFile.getPathname();
                if (pathname != null && !pathname.isEmpty()) {
                    Path path = Paths.get(pathname);
                    Path parent = path.getParent();
                    if (parent != null) {
                        return parent.resolve(".zenyard").resolve("copilot")
                            .resolve(sanitizeName(program.getName()));
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to resolve program storage path: " + e.getMessage());
        }
        return Paths.get(System.getProperty("user.home"), ".zenyard", "copilot", sanitizeName(program.getName()));
    }

    private String sanitizeName(String name) {
        if (name == null || name.isBlank()) {
            return "unknown_program";
        }
        return name.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
