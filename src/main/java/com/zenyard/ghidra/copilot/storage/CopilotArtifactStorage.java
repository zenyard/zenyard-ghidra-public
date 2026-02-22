package com.zenyard.ghidra.copilot.storage;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
