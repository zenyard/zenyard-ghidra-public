package com.zenyard.ghidra.ui;

import java.awt.BorderLayout;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import java.awt.Color;

import com.zenyard.ghidra.usage.UsageLevel;
import com.zenyard.ghidra.usage.UsageState;
import ghidra.framework.plugintool.PluginTool;

public class UsageDetailsDialog extends ZenyardDialogComponentProvider {
    private final UsageState usageState;

    public UsageDetailsDialog(UsageState usageState) {
        super("Usage", true);
        this.usageState = usageState != null ? usageState : UsageState.unknown();
        buildPanel();
    }

    private void buildPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout());
        JPanel titlePanel = createTitlePanel("Current Package Usage");
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
        String usageText = usageState.getDisplayTextForDialog();
        if (usageText == null || usageText.isEmpty()) {
            usageText = "Not available";
        }
        JLabel usageValueLabel = new JLabel(usageText);
        UsageLevel level = usageState.getDisplayLevel();
        if (level == UsageLevel.WARNING || level == UsageLevel.OVER_LIMIT || level == UsageLevel.EXPIRED) {
            usageValueLabel.setForeground(Color.RED);
        }
        mainPanel.add(usageValueLabel, gbc);

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
            : "For more usage or top-ups, " + UsageState.getContactSupportText();
        mainPanel.add(createGuidanceComponent(guidance), gbc);

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

    private JPanel createGuidanceComponent(String guidance) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        panel.setOpaque(false);
        String text = guidance == null ? "" : guidance;
        String clickableText = "Contact us";
        int clickableIndex = text.indexOf(clickableText);
        if (clickableIndex < 0) {
            panel.add(new JLabel(text));
            return panel;
        }
        if (!UsageState.isContactEmailSupported()) {
            String display = text.contains(UsageState.CONTACT_EMAIL)
                ? text
                : text.replace(clickableText, UsageState.getContactSupportText());
            panel.add(new JLabel(display));
            return panel;
        }

        String before = text.substring(0, clickableIndex);
        String after = text.substring(clickableIndex + clickableText.length())
            .replace(": " + UsageState.CONTACT_EMAIL, "");

        if (!before.isEmpty()) {
            panel.add(new JLabel(before));
        }

        JLabel contactLink = new JLabel("<html><u>" + clickableText + "</u></html>");
        contactLink.setForeground(new Color(0, 102, 204));
        contactLink.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        contactLink.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                UsageState.openContactEmail();
            }
        });
        panel.add(contactLink);

        if (!after.isEmpty()) {
            panel.add(new JLabel(after));
        }
        return panel;
    }
}
