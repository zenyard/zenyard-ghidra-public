package com.zenyard.ghidra.ui;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import com.zenyard.ghidra.usage.UsageState;
import ghidra.framework.plugintool.PluginTool;

public class UsageDetailsDialog extends ZenyardDialogComponentProvider {
    private final UsageState usageState;

    public UsageDetailsDialog(UsageState usageState) {
        super("Zenyard Usage", true);
        this.usageState = usageState != null ? usageState : UsageState.unknown();
        buildPanel();
    }

    private void buildPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout());
        JPanel titlePanel = createTitlePanel("Zenyard Usage");
        contentPanel.add(titlePanel, BorderLayout.NORTH);

        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx = 0;
        gbc.gridy = 0;

        mainPanel.add(new JLabel("Plan:"), gbc);
        gbc.gridx = 1;
        mainPanel.add(new JLabel(usageState.getPlanLabel()), gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        mainPanel.add(new JLabel("Usage:"), gbc);
        gbc.gridx = 1;
        String usageText = usageState.getDisplayText();
        if (usageText == null || usageText.isEmpty()) {
            usageText = "Not available";
        }
        mainPanel.add(new JLabel(usageText), gbc);

        if (usageState.getExpiration() != null && !usageState.getExpiration().isEmpty()) {
            gbc.gridx = 0;
            gbc.gridy++;
            mainPanel.add(new JLabel("Expiration:"), gbc);
            gbc.gridx = 1;
            mainPanel.add(new JLabel(usageState.getExpiration()), gbc);
        }

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.gridwidth = 2;
        String guidance = usageState.isBlocked()
            ? usageState.getBlockedMessage()
            : "For more usage or top-ups, contact Zenyard support.";
        mainPanel.add(new JLabel("<html>" + guidance + "</html>"), gbc);

        contentPanel.add(mainPanel, BorderLayout.CENTER);
        addWorkPanel(contentPanel);
        addOKButton();
    }

    @Override
    protected void okCallback() {
        close();
    }

    public static void showDialog(PluginTool tool, UsageState usageState) {
        UsageDetailsDialog dialog = new UsageDetailsDialog(usageState);
        tool.showDialog(dialog);
    }
}
