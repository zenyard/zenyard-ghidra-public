package com.zenyard.ghidra.config;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;

import docking.widgets.label.GDLabel;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;

import com.zenyard.ghidra.ZenyardGhidraPlugin;
import com.zenyard.ghidra.ui.ZenyardDialogComponentProvider;

/**
 * Multi-step onboarding dialog for Welcome, EULA, and Configuration.
 */
public class OnboardingDialog extends ZenyardDialogComponentProvider {
    private static final String STEP_WELCOME = "welcome";
    private static final String STEP_EULA = "eula";
    private static final String STEP_CONFIG = "config";

    private final PluginTool tool;
    private final ZenyardOptions options;
    private final String[] steps = { STEP_WELCOME, STEP_EULA, STEP_CONFIG };

    private JPanel cardPanel;
    private CardLayout cardLayout;
    private int stepIndex;
    private JCheckBox eulaCheckBox;
    private JButton backButton;
    private JButton nextButton;
    private JButton cancelButton;
    private LicenseConfigPanel configPanel;
    private boolean accepted;

    public OnboardingDialog(PluginTool tool, ZenyardOptions options) {
        // Dialog/window title (OS title bar); header bar text is controlled separately via createTitlePanel(...)
        super("Hello, reverse engineer", true);
        this.tool = tool;
        this.options = options;
        this.stepIndex = 0;
        this.accepted = false;
        buildPanel();
        updateButtonState();
    }

    private void buildPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout());
        JPanel titlePanel = createTitlePanel(getHeaderTitleForStep());
        contentPanel.add(titlePanel, BorderLayout.NORTH);

        cardLayout = new CardLayout();
        cardPanel = new JPanel(cardLayout);
        cardPanel.add(buildWelcomePanel(), STEP_WELCOME);
        cardPanel.add(buildEulaPanel(), STEP_EULA);
        cardPanel.add(buildConfigPanel(), STEP_CONFIG);

        contentPanel.add(cardPanel, BorderLayout.CENTER);
        addWorkPanel(contentPanel);

        backButton = new JButton("Back");
        nextButton = new JButton("Next");
        cancelButton = new JButton("Cancel");

        backButton.addActionListener(e -> goBack());
        nextButton.addActionListener(e -> goNext());
        cancelButton.addActionListener(e -> cancel());

        addButton(backButton);
        addButton(nextButton);
        addButton(cancelButton);

        Dimension baseSize = getPreferredSize();
        if (baseSize != null && baseSize.width > 0 && baseSize.height > 0) {
            Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            int maxHeight = (int) Math.round(screenSize.height * 0.35);
            int targetWidth = baseSize.width;
            int targetHeight = Math.min(baseSize.height, maxHeight);
            setPreferredSize(targetWidth, targetHeight);
        }
    }

    private JPanel buildWelcomePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridx = 0;
        gbc.gridy = 0;

        GDLabel titleLabel = new GDLabel("Welcome to Zenyard");
        Font baseFont = titleLabel.getFont();
        titleLabel.setFont(baseFont.deriveFont(Font.BOLD));
        panel.add(titleLabel, gbc);

        gbc.gridy++;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0;
        JTextArea descriptionArea = new JTextArea(getPluginDescription());
        descriptionArea.setEditable(false);
        descriptionArea.setFocusable(false);
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);
        descriptionArea.setOpaque(false);
        descriptionArea.setFont(baseFont);
        panel.add(descriptionArea, gbc);

        return panel;
    }

    private JPanel buildEulaPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridx = 0;
        gbc.gridy = 0;

        JLabel introLabel = new JLabel("Please review and accept the following Terms of Use:");
        Font baseFont = introLabel.getFont();
        panel.add(introLabel, gbc);

        gbc.gridy++;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0;
        JTextArea textArea = new JTextArea(EulaDialog.getEulaText());
        textArea.setEditable(false);
        textArea.setFocusable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setFont(baseFont.deriveFont((float) Math.max(baseFont.getSize(), 12)));

        JScrollPane scrollPane = new JScrollPane(textArea);
        panel.add(scrollPane, gbc);

        gbc.gridy++;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weighty = 0.0;
        eulaCheckBox = new JCheckBox("I have read and accept the Terms of Use");
        eulaCheckBox.addItemListener(e -> updateButtonState());
        panel.add(eulaCheckBox, gbc);

        return panel;
    }

    private JPanel buildConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        configPanel = new LicenseConfigPanel(tool, options, this::setStatusText);
        panel.add(configPanel, BorderLayout.CENTER);
        return panel;
    }

    private void goBack() {
        if (stepIndex > 0) {
            stepIndex--;
            showStep();
        }
    }

    private void goNext() {
        if (stepIndex >= steps.length - 1) {
            if (configPanel.saveConfiguration()) {
                accepted = true;
                close();
            }
            return;
        }
        stepIndex++;
        showStep();
    }

    private void cancel() {
        accepted = false;
        close();
    }

    private void showStep() {
        cardLayout.show(cardPanel, steps[stepIndex]);
        updateTitlePanel(getHeaderTitleForStep());
        updateButtonState();
    }

    private void updateButtonState() {
        backButton.setEnabled(stepIndex > 0);
        boolean nextEnabled = true;
        if (STEP_EULA.equals(steps[stepIndex])) {
            nextEnabled = eulaCheckBox != null && eulaCheckBox.isSelected();
        }
        nextButton.setEnabled(nextEnabled);
        nextButton.setText(stepIndex == steps.length - 1 ? "Finish" : "Next");
    }

    private String getHeaderTitleForStep() {
        if (STEP_EULA.equals(steps[stepIndex])) {
            return "The Fine Print";
        }
        if (STEP_CONFIG.equals(steps[stepIndex])) {
            return "Wire It Up (API Key + Server URL)";
        }
        return "Zenyard Setup";
    }


    private String getPluginDescription() {
        PluginInfo info = ZenyardGhidraPlugin.class.getAnnotation(PluginInfo.class);
        if (info == null) {
            return "";
        }
        return normalizeDescription(info.description());
    }

    private String normalizeDescription(String description) {
        if (description == null) {
            return "";
        }
        return description.replace("themeaningful", "the meaningful").trim();
    }

    public boolean isAccepted() {
        return accepted;
    }

    /**
     * Show the dialog and return whether the user completed onboarding.
     */
    public static boolean showDialog(PluginTool tool, ZenyardOptions options) {
        OnboardingDialog dialog = new OnboardingDialog(tool, options);
        tool.showDialog(dialog);
        return dialog.isAccepted();
    }
}
