package com.zenyard.decompai.ghidra.config;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;

import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import java.util.concurrent.CompletableFuture;

import com.zenyard.decompai.ghidra.api.generated.ApiClient;
import com.zenyard.decompai.ghidra.api.generated.ApiException;
import com.zenyard.decompai.ghidra.api.generated.api.UserApi;

/**
 * Configuration dialog for DecompAI API key and server settings.
 * 
 * NOTE: mirrors functionality in decompai_ida/configuration.py show_configuration_dialog_sync()
 */
public class LicenseConfigDialog extends DialogComponentProvider {
    
    private final DecompaiOptions options;
    private final PluginTool tool;
    private JTextField apiKeyField;
    private JTextField serverUrlField;
    private JButton testConnectionButton;
    
    public LicenseConfigDialog(PluginTool tool, DecompaiOptions options) {
        super("DecompAI Configuration", true, true, true, false);
        this.tool = tool;
        this.options = options;
        
        buildPanel();
        initializeFields();
    }
    
    private void buildPanel() {
        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // API Key label
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        mainPanel.add(new JLabel("API Key:"), gbc);
        
        // API Key field
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        apiKeyField = new JPasswordField(40);
        mainPanel.add(apiKeyField, gbc);
        
        // Server URL label
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        mainPanel.add(new JLabel("Server URL:"), gbc);
        
        // Server URL field
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        serverUrlField = new JTextField(40);
        mainPanel.add(serverUrlField, gbc);
        
        // Test Connection button
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        testConnectionButton = new JButton("Test Connection");
        testConnectionButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                testConnection();
            }
        });
        mainPanel.add(testConnectionButton, gbc);
        
        addWorkPanel(mainPanel);
        
        // Buttons
        addOKButton();
        addCancelButton();
    }
    
    private void initializeFields() {
        // Read current values from config file
        apiKeyField.setText(options.getApiKey());
        serverUrlField.setText(options.getServerUrl());
    }
    
    private void testConnection() {
        String apiKey = apiKeyField.getText().trim();
        String serverUrl = serverUrlField.getText().trim();
        
        if (apiKey.isEmpty()) {
            setStatusText("Please enter an API key");
            return;
        }
        
        if (serverUrl.isEmpty()) {
            setStatusText("Please enter a server URL");
            return;
        }
        
        // Validate URL format
        try {
            new java.net.URL(serverUrl);
        } catch (java.net.MalformedURLException e) {
            setStatusText("Invalid URL format: " + e.getMessage());
            return;
        }
        
        setStatusText("Testing connection...");
        testConnectionButton.setEnabled(false);
        
        // Test connection using API client
        String baseUrl = serverUrl.endsWith("/") ? serverUrl.substring(0, serverUrl.length() - 1) : serverUrl;
        ApiClient testClient = new ApiClient();
        // Use updateBaseUri() to properly parse the full URL and set scheme, host, port, and basePath
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
                setStatusText("Connection successful!");
                testConnectionButton.setEnabled(true);
            });
        })
        .exceptionally(throwable -> {
            java.awt.EventQueue.invokeLater(() -> {
                String errorMsg = "Connection failed: " + throwable.getMessage();
                if (throwable.getCause() != null) {
                    errorMsg = "Connection failed: " + throwable.getCause().getMessage();
                }
                setStatusText(errorMsg);
                testConnectionButton.setEnabled(true);
            });
            return null;
        });
    }
    
    @Override
    protected void okCallback() {
        String apiKey = apiKeyField.getText().trim();
        String serverUrl = serverUrlField.getText().trim();
        
        // Validate
        if (apiKey.isEmpty()) {
            setStatusText("API key cannot be empty");
            return;
        }
        
        if (serverUrl.isEmpty()) {
            setStatusText("Server URL cannot be empty");
            return;
        }
        
        try {
            new java.net.URL(serverUrl);
        } catch (java.net.MalformedURLException e) {
            setStatusText("Invalid URL format: " + e.getMessage());
            return;
        }
        
        // Write to config file (matching IDA's with_user_config pattern)
        try {
            PluginConfiguration current = options.getConfiguration();
            PluginConfiguration updated = current.withUserConfig(serverUrl, apiKey);
            DecompaiConfigFile.writeConfiguration(updated);
            
            // Reload options to get updated values
            options.reloadConfiguration();
            
            Msg.info(this, "DecompAI configuration saved to decompai.json");
            close();
        } catch (java.io.IOException e) {
            setStatusText("Failed to save configuration: " + e.getMessage());
            Msg.showError(this, tool.getActiveWindow(), "Save Error",
                "Failed to save configuration to decompai.json", e);
        }
    }
    
    @Override
    protected void cancelCallback() {
        close();
    }
}

