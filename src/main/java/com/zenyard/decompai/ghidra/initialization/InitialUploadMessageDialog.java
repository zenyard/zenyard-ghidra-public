package com.zenyard.decompai.ghidra.initialization;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Map;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import com.zenyard.decompai.ghidra.config.DecompaiOptions;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;
import com.zenyard.decompai.ghidra.upload.QueueRevisionsTask;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;

/**
 * Dialog shown after initial upload completes.
 * 
 * Mirrors IDA's ShowInitialUploadMessageTask.
 * 
 * NOTE: mirrors decompai_ida/show_initial_upload_message_task.py
 */
public class InitialUploadMessageDialog extends DialogComponentProvider {
    
    private final DecompaiOptions options;
    private final PluginTool tool;
    private JCheckBox dontShowAgainCheckBox;
    
    public InitialUploadMessageDialog(PluginTool tool, DecompaiOptions options) {
        super("Zenyard Is Now Analyzing in the Background", true, true, true, false);
        this.tool = tool;
        this.options = options;
        
        buildPanel();
    }
    
    private void buildPanel() {
        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Message
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        JLabel messageLabel = new JLabel(
            "<html>The initial processing is complete. Zenyard will continue analyzing remotely in the background.<br><br>" +
            "You can safely close Ghidra — no need to keep it running.</html>");
        mainPanel.add(messageLabel, gbc);
        
        // Don't show again checkbox
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        dontShowAgainCheckBox = new JCheckBox("Don't show this message again");
        mainPanel.add(dontShowAgainCheckBox, gbc);
        
        addWorkPanel(mainPanel);
        
        // Buttons
        addOKButton();
    }
    
    @Override
    protected void okCallback() {
        if (dontShowAgainCheckBox.isSelected()) {
            try {
                // Partial update - only update show_initial_upload_message
                options.updateConfiguration(Map.of(
                    "show_initial_upload_message", false
                ));
            } catch (java.io.IOException e) {
                Msg.showError(this, tool.getActiveWindow(), "Configuration Error",
                    "Failed to update configuration: " + e.getMessage(), e);
            }
        }
        Msg.info(this, "DecompAI: Initial upload message acknowledged");
        close();
    }
    
    /**
     * Show the dialog if it should be shown.
     * 
     * Mirrors IDA's ShowInitialUploadMessageTask logic:
     * - Returns early if user disabled the message
     * - Returns early if initial_upload_complete is already true (upload was done before we started)
     * - Waits for initial_upload_complete to become true
     * - Only shows once per program (tracks via program properties)
     */
    public static void showDialogIfNeeded(PluginTool tool, DecompaiOptions options, Program program) {
        Msg.info(InitialUploadMessageDialog.class, "InitialUploadMessageDialog.showDialogIfNeeded() called");
        
        if (program == null || program.isClosed()) {
            Msg.warn(InitialUploadMessageDialog.class, "Cannot show dialog - program is null or closed");
            return;
        }
        
        if (!options.isShowInitialUploadMessage()) {
            Msg.info(InitialUploadMessageDialog.class, "Dialog disabled by user configuration");
            return; // User disabled this message
        }
        
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        
        // Check if initial upload is already complete - if so, show dialog immediately
        // This handles the case where the upload was already done before we started
        String initialUploadComplete = props.getString("initial_upload_complete");
        Msg.info(InitialUploadMessageDialog.class, "initial_upload_complete property: " + initialUploadComplete);
        
        if ("true".equals(initialUploadComplete)) {
            // Upload was already complete - check if dialog was already shown
            String dialogShown = props.getString("initial_upload_message_shown");
            Msg.info(InitialUploadMessageDialog.class, "initial_upload_message_shown property: " + dialogShown);
            
            if ("true".equals(dialogShown)) {
                Msg.info(InitialUploadMessageDialog.class, "Dialog already shown for this program, skipping");
                return; // Dialog was already shown for this program
            }
            // Upload is complete but dialog hasn't been shown - show it now
            Msg.info(InitialUploadMessageDialog.class, "Showing InitialUploadMessageDialog");
            showDialogAndMarkShown(tool, options, program, props);
            return;
        }
        
        Msg.info(InitialUploadMessageDialog.class, "Initial upload not complete yet, waiting for INITIAL_UPLOAD_COMPLETE event");
        // Upload not complete yet - the dialog will be shown via event handler
        // when INITIAL_UPLOAD_COMPLETE event is received
    }
    
    /**
     * Show the dialog and mark it as shown in program properties.
     */
    private static void showDialogAndMarkShown(PluginTool tool, DecompaiOptions options,
                                               Program program, DecompaiProgramProperties props) {
        // Mark dialog as shown before displaying (to prevent duplicate shows)
        props.setString("initial_upload_message_shown", "true");

        InitialUploadMessageDialog dialog = new InitialUploadMessageDialog(tool, options);
        tool.showDialog(dialog);
    }
    ;
}
