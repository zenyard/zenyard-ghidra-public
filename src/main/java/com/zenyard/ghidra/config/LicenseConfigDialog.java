package com.zenyard.ghidra.config;

import java.awt.BorderLayout;

import javax.swing.JPanel;

import ghidra.framework.plugintool.PluginTool;
import com.zenyard.ghidra.ui.ZenyardDialogComponentProvider;

/**
 * Configuration dialog for Zenyard API key and server settings.
 * 
 * NOTE: mirrors functionality in zenyard_ida/configuration.py show_configuration_dialog_sync()
 */
public class LicenseConfigDialog extends ZenyardDialogComponentProvider {
    
    private final ZenyardOptions options;
    private final PluginTool tool;
    private LicenseConfigPanel configPanel;
    
    public LicenseConfigDialog(PluginTool tool, ZenyardOptions options) {
        super("Zenyard Configuration", true);
        this.tool = tool;
        this.options = options;
        
        buildPanel();
    }
    
    private void buildPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout());
        JPanel titlePanel = createTitlePanel("Zenyard Configuration");
        contentPanel.add(titlePanel, BorderLayout.NORTH);

        configPanel = new LicenseConfigPanel(tool, options, this::setStatusText);
        
        contentPanel.add(configPanel, BorderLayout.CENTER);
        addWorkPanel(contentPanel);
        
        // Buttons
        addOKButton();
        addCancelButton();
    }
    
    @Override
    protected void okCallback() {
        if (configPanel.saveConfiguration()) {
            close();
        }
    }
    
    @Override
    protected void cancelCallback() {
        close();
    }
}

