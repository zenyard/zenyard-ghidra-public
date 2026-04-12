package com.zenyard.ghidra.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ZenyardConfigFileTest {

    @TempDir
    private Path tempDir;

    private String originalUserHome;

    @BeforeEach
    void setUp() {
        originalUserHome = System.getProperty("user.home");
        System.setProperty("user.home", tempDir.toString());
    }

    @AfterEach
    void tearDown() {
        if (originalUserHome != null) {
            System.setProperty("user.home", originalUserHome);
        }
    }

    @Test
    void createDefaultConfigurationCreatesFileWithDefaults() throws IOException {
        Path configPath = ZenyardConfigFile.getConfigPath();
        assertFalse(Files.exists(configPath));

        PluginConfiguration config = ZenyardConfigFile.createDefaultConfiguration();
        PluginConfiguration defaultConfig = PluginConfiguration.getDefault();

        assertTrue(Files.exists(configPath));
        assertEquals(defaultConfig.getApiUrl(), config.getApiUrl());
        assertEquals(defaultConfig.getApiKey(), config.getApiKey());
        assertEquals(defaultConfig.getLogLevel(), config.getLogLevel());
        assertEquals(defaultConfig.isShowInitialUploadMessage(), config.isShowInitialUploadMessage());
        assertEquals(defaultConfig.isRequestBinaryInstructions(), config.isRequestBinaryInstructions());
        assertEquals(defaultConfig.isRequireConfirmationPerDb(), config.isRequireConfirmationPerDb());
        assertEquals(defaultConfig.isVerifySsl(), config.isVerifySsl());
        assertEquals(defaultConfig.getAcceptedEulaVersion(), config.getAcceptedEulaVersion());

        String json = Files.readString(configPath);
        assertTrue(json.contains("\"api_url\""));
    }
}
