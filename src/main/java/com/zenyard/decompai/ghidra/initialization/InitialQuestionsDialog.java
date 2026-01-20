package com.zenyard.decompai.ghidra.initialization;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;

import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import com.zenyard.decompai.ghidra.config.DecompaiOptions;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;

/**
 * Dialog shown after initial analysis completes, asking user if they want to start Zenyard analysis.
 * 
 * Mirrors IDA's ShowInitialQuestionsTask.
 * 
 * NOTE: mirrors decompai_ida/ask_initial_questions_task.py
 */
public class InitialQuestionsDialog extends DialogComponentProvider {
    
    /**
     * Result of the dialog.
     */
    public static class InitialQuestionsResult {
        private final boolean accepted;
        private final boolean autoApplyResults;
        private final boolean allowPreprocessing;
        private final String binaryInstructions;
        
        public InitialQuestionsResult(boolean accepted, boolean autoApplyResults, 
                boolean allowPreprocessing, String binaryInstructions) {
            this.accepted = accepted;
            this.autoApplyResults = autoApplyResults;
            this.allowPreprocessing = allowPreprocessing;
            this.binaryInstructions = binaryInstructions;
        }
        
        public boolean isAccepted() {
            return accepted;
        }
        
        public boolean isAutoApplyResults() {
            return autoApplyResults;
        }
        
        public boolean isAllowPreprocessing() {
            return allowPreprocessing;
        }
        
        public String getBinaryInstructions() {
            return binaryInstructions;
        }
    }
    
    private final DecompaiOptions options;
    private final Program program;
    private JCheckBox autoApplyCheckBox;
    private JCheckBox allowPreprocessingCheckBox;
    private JCheckBox dontShowAgainCheckBox;
    private JTextArea binaryInstructionsArea;
    private InitialQuestionsResult result;
    
    public InitialQuestionsDialog(PluginTool tool, DecompaiOptions options, Program program) {
        super("Run Zenyard Analysis", true, true, true, false);
        this.options = options;
        this.program = program;
        this.result = null;
        
        buildPanel();
    }
    
    private void buildPanel() {
        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Description
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        JLabel descriptionLabel = new JLabel(
            "<html>Looks like it's your first time opening this file — Zenyard can analyze it now to save you time and effort.</html>");
        mainPanel.add(descriptionLabel, gbc);
        
        // Auto-apply checkbox
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        autoApplyCheckBox = new JCheckBox("Auto-apply results when ready", true);
        mainPanel.add(autoApplyCheckBox, gbc);
        
        // Allow preprocessing checkbox
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        allowPreprocessingCheckBox = new JCheckBox("Allow Zenyard to improve database before uploading", true);
        mainPanel.add(allowPreprocessingCheckBox, gbc);
        
        // Binary instructions (if enabled)
        int nextRow = 3;
        if (options.isRequestBinaryInstructions()) {
            gbc.gridx = 0;
            gbc.gridy = nextRow++;
            gbc.gridwidth = 2;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.weighty = 1.0;
            JLabel instructionsLabel = new JLabel(
                "<html>To improve the analysis, add any details you know (source, purpose, structure, etc.) or just click OK to continue.<br>Only share what you're sure about.</html>");
            mainPanel.add(instructionsLabel, gbc);
            
            gbc.gridx = 0;
            gbc.gridy = nextRow++;
            gbc.gridwidth = 2;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.weighty = 1.0;
            binaryInstructionsArea = new JTextArea(5, 40);
            binaryInstructionsArea.setLineWrap(true);
            binaryInstructionsArea.setWrapStyleWord(true);
            mainPanel.add(binaryInstructionsArea, gbc);
        }
        
        // Don't show again checkbox
        gbc.gridx = 0;
        gbc.gridy = nextRow;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weighty = 0.0;
        dontShowAgainCheckBox = new JCheckBox("Don't show this dialog again for this project");
        mainPanel.add(dontShowAgainCheckBox, gbc);
        
        addWorkPanel(mainPanel);
        
        // Buttons
        addOKButton();
        addCancelButton();
    }
    
    @Override
    protected void okCallback() {
        String binaryInstructions = null;
        if (options.isRequestBinaryInstructions() && binaryInstructionsArea != null) {
            String text = binaryInstructionsArea.getText().trim();
            if (!text.isEmpty()) {
                binaryInstructions = text;
            }
        }
        
        result = new InitialQuestionsResult(
            true,
            autoApplyCheckBox.isSelected(),
            allowPreprocessingCheckBox.isSelected(),
            binaryInstructions
        );
        
        // Store "don't show again" preference if checked
        if (dontShowAgainCheckBox.isSelected() && program != null) {
            DecompaiProgramProperties props = new DecompaiProgramProperties(program);
            props.setString("dont_show_initial_questions_again", "true");
        }
        
        Msg.info(this, "DecompAI: User accepted initial questions");
        close();
    }
    
    @Override
    protected void cancelCallback() {
        result = new InitialQuestionsResult(false, false, false, null);
        
        // Store "don't show again" preference if checked (even on cancel)
        if (dontShowAgainCheckBox.isSelected() && program != null) {
            DecompaiProgramProperties props = new DecompaiProgramProperties(program);
            props.setString("dont_show_initial_questions_again", "true");
        }
        
        Msg.info(this, "DecompAI: User skipped initial questions");
        close();
    }
    
    /**
     * Show the dialog and return the result.
     */
    public static InitialQuestionsResult showDialog(PluginTool tool, DecompaiOptions options, 
            Program program) {
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        
        // Check "don't show again" property first (before other checks)
        String dontShowAgain = props.getString("dont_show_initial_questions_again");
        if ("true".equals(dontShowAgain)) {
            return null; // User requested not to show again for this project
        }
        
        // Check if already asked
        String alreadyAsked = props.getString("asked_initial_questions");
        if ("true".equals(alreadyAsked)) {
            return null; // Already asked, don't show again
        }
        
        // Check if already uploaded
        String alreadyUploaded = props.getString("initial_upload_complete");
        if ("true".equals(alreadyUploaded)) {
            return null; // Already uploaded, don't show
        }
        
        InitialQuestionsDialog dialog = new InitialQuestionsDialog(tool, options, program);
        tool.showDialog(dialog);
        
        InitialQuestionsResult result = dialog.result;
        
        // Store that we asked only if user accepted (not if they cancel)
        if (result != null && result.isAccepted()) {
            props.setString("asked_initial_questions", "true");
        }
        
        return result;
    }
}

