package com.zenyard.ghidra.config;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.function.BiConsumer;
import java.util.concurrent.CompletableFuture;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.MessageType;

import com.zenyard.ghidra.api.generated.ApiClient;
import com.zenyard.ghidra.api.generated.ApiException;
import com.zenyard.ghidra.api.generated.api.UserApi;
import com.zenyard.ghidra.polling.ConnectionErrorHandler;

/**
 * Reusable configuration panel for Zenyard API key and server settings.
 */
public class LicenseConfigPanel extends JPanel {

    private final ZenyardOptions options;
    private final PluginTool tool;
    private final BiConsumer<String, MessageType> statusSetter;
    private JTextField apiKeyField;
    private JTextField serverUrlField;
    private JButton testConnectionButton;

    public LicenseConfigPanel(PluginTool tool, ZenyardOptions options,
            BiConsumer<String, MessageType> statusSetter) {
        super(new GridBagLayout());
        this.tool = tool;
        this.options = options;
        this.statusSetter = statusSetter;
        setBorder(new EmptyBorder(10, 10, 10, 10));
        buildPanel();
        initializeFields();
    }

    private void buildPanel() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // API Key label
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        add(new JLabel("API Key:"), gbc);

        // API Key field
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        apiKeyField = new JPasswordField(40);
        add(apiKeyField, gbc);

        // Server URL label
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        add(new JLabel("Server URL:"), gbc);

        // Server URL field
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        serverUrlField = new JTextField(40);
        add(serverUrlField, gbc);

        // Test Connection button
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        testConnectionButton = new JButton("Test Connection");
        testConnectionButton.addActionListener(e -> testConnection());
        add(testConnectionButton, gbc);
    }

    private void initializeFields() {
        apiKeyField.setText(options.getApiKey());
        serverUrlField.setText(options.getServerUrl());
    }

    private void setStatusText(String message, MessageType type) {
        if (statusSetter != null) {
            statusSetter.accept(message, type);
        }
    }

    private String validateInputs() {
        String apiKey = apiKeyField.getText().trim();
        String serverUrl = serverUrlField.getText().trim();

        if (apiKey.isEmpty()) {
            return "API key cannot be empty";
        }
        if (serverUrl.isEmpty()) {
            return "Server URL cannot be empty";
        }
        try {
            new java.net.URI(serverUrl).toURL();
        } catch (Exception e) {
            return "Invalid URL format: " + e.getMessage();
        }
        return null;
    }

    public boolean saveConfiguration() {
        String validationError = validateInputs();
        if (validationError != null) {
            setStatusText(validationError, MessageType.ERROR);
            return false;
        }

        String apiKey = apiKeyField.getText().trim();
        String serverUrl = serverUrlField.getText().trim();

        try {
            PluginConfiguration current = options.getConfiguration();
            PluginConfiguration updated = current.withUserConfig(serverUrl, apiKey);
            ZenyardConfigFile.writeConfiguration(updated);

            options.reloadConfiguration();
            Msg.info(this, "Zenyard configuration saved to zenyard.json");
            return true;
        } catch (java.io.IOException e) {
            setStatusText("Failed to save configuration: " + e.getMessage(), MessageType.ERROR);
            Msg.showError(this, tool.getActiveWindow(), "Save Error",
                "Failed to save configuration to zenyard.json", e);
            return false;
        }
    }

    private void testConnection() {
        String apiKey = apiKeyField.getText().trim();
        String serverUrl = serverUrlField.getText().trim();

        if (apiKey.isEmpty()) {
            setStatusText("Please enter an API key", MessageType.ERROR);
            return;
        }

        if (serverUrl.isEmpty()) {
            setStatusText("Please enter a server URL", MessageType.ERROR);
            return;
        }

        try {
            new java.net.URI(serverUrl).toURL();
        } catch (Exception e) {
            setStatusText("Invalid URL format: " + e.getMessage(), MessageType.ERROR);
            return;
        }

        setStatusText("Testing connection...", MessageType.INFO);
        testConnectionButton.setEnabled(false);

        String baseUrl = serverUrl.endsWith("/") ? serverUrl.substring(0, serverUrl.length() - 1) : serverUrl;
        ApiClient testClient = new ApiClient();
        testClient.updateBaseUri(baseUrl);
        testClient.setRequestInterceptor((java.net.http.HttpRequest.Builder builder) -> {
            builder.header("X-API-Key", apiKey);
        });
        UserApi userApi = new UserApi(testClient);

        CompletableFuture.supplyAsync(() -> {
            try {
                return userApi.getUserConfig();
            } catch (ApiException e) {
                throw new RuntimeException(e);
            }
        }).thenAccept(response -> {
            java.awt.EventQueue.invokeLater(() -> {
                setStatusText("Connection successful!", MessageType.INFO);
                testConnectionButton.setEnabled(true);
            });
        })
        .exceptionally(throwable -> {
            Throwable rootCause = ConnectionErrorHandler.findRootCause(throwable);
            String statusMessage = getConnectionStatusMessage(rootCause);
            java.awt.EventQueue.invokeLater(() -> {
                setStatusText(statusMessage, MessageType.ERROR);
                testConnectionButton.setEnabled(true);
            });
            return null;
        });
    }

    private String getConnectionStatusMessage(Throwable rootCause) {
        if (rootCause instanceof ApiException) {
            ApiException apiException = (ApiException) rootCause;
            if (apiException.getCode() == 401) {
                return "Invalid API key";
            }
        } else if (ConnectionErrorHandler.isConnectionError(rootCause)) {
            return "Server not responding";
        }
        return "Connection failed";
    }
}
