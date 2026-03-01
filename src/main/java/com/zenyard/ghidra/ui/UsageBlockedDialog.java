package com.zenyard.ghidra.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import com.zenyard.ghidra.usage.UsageState;

public final class UsageBlockedDialog {

    private UsageBlockedDialog() {
    }

    public static void showDialog(Component parent, UsageState state) {
        UsageState resolved = state != null ? state : UsageState.unknown();
        Runnable showTask = () -> JOptionPane.showMessageDialog(
            parent,
            createContentPanel(resolved),
            UsageState.BLOCKED_DIALOG_TITLE,
            JOptionPane.ERROR_MESSAGE);
        if (SwingUtilities.isEventDispatchThread()) {
            showTask.run();
        } else {
            SwingUtilities.invokeLater(showTask);
        }
    }

    private static JPanel createContentPanel(UsageState state) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(4, 0, 0, 0));

        JTextArea messageArea = new JTextArea(state.getBlockedMessage());
        messageArea.setEditable(false);
        messageArea.setOpaque(false);
        messageArea.setLineWrap(true);
        messageArea.setWrapStyleWord(true);
        messageArea.setFocusable(false);
        messageArea.setBorder(null);
        panel.add(messageArea, BorderLayout.NORTH);

        panel.add(createContactPanel(), BorderLayout.SOUTH);
        return panel;
    }

    private static JPanel createContactPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 6));
        panel.setOpaque(false);
        if (UsageState.isContactEmailSupported()) {
            panel.add(createContactLinkLabel());
            panel.add(new JLabel(" "));
        }
        panel.add(new JLabel(UsageState.getContactSupportText()));
        return panel;
    }

    private static JLabel createContactLinkLabel() {
        JLabel contactLabel = new JLabel("<html><u>Contact us</u></html>");
        contactLabel.setForeground(new Color(0, 102, 204));
        contactLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        contactLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                UsageState.openContactEmail();
            }
        });
        return contactLabel;
    }
}
