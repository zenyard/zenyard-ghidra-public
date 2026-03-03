package com.zenyard.ghidra.ui;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import ghidra.util.Msg;

import com.zenyard.ghidra.config.ZenyardOptions;

/**
 * Dialog shown when the Python runtime is unavailable for Copilot tools.
 */
public class PythonUnavailableDialog extends ZenyardDialogComponentProvider {

    private final ZenyardOptions options;
    private JCheckBox dontShowAgainCheckBox;

    public PythonUnavailableDialog(ZenyardOptions options) {
        super("Notification", true);
        this.options = options;
        buildPanel();
    }

    private void buildPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(createTitlePanel("Python Runtime Unavailable"), BorderLayout.NORTH);

        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        JLabel messageLabel = new JLabel(
            "<html>Copilot Python tooling is unavailable in this Ghidra session.<br><br>"
                + "For best Copilot results, start Ghidra using <b>pyghidraRun</b> "
                + "instead of launchers like ghidraRun or ghidraDebug.</html>");
        mainPanel.add(messageLabel, gbc);

        gbc.gridy = 1;
        dontShowAgainCheckBox = new JCheckBox("Don't show this again");
        mainPanel.add(dontShowAgainCheckBox, gbc);

        contentPanel.add(mainPanel, BorderLayout.CENTER);
        addWorkPanel(contentPanel);
        addOKButton();
    }

    @Override
    protected void okCallback() {
        if (dontShowAgainCheckBox.isSelected()) {
            try {
                options.updateConfiguration(
                    java.util.Map.of("show_python_unavailable_popup", false));
            } catch (Exception e) {
                Msg.warn(this, "Failed to save popup preference: " + e.getMessage());
            }
        }
        close();
    }
}
