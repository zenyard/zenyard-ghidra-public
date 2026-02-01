package com.zenyard.ghidra.status;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;

import docking.widgets.label.GDLabel;
import ghidra.framework.plugintool.PluginTool;

/**
 * Status bar component that renders from a view model and forwards actions.
 */
public class StatusBarComponent extends JPanel {
    private static final int ICON_SIZE = 20;
    private static final int PANEL_HEIGHT = 25;
    private static final int PROGRESS_WIDTH = 100;
    private static final int SPACING_SMALL = 2;
    private static final int SPACING_MEDIUM = 4;

    private final StatusBarViewModel viewModel;
    @SuppressWarnings("unused")
    private final StatusBarActions actions;
    private final IconRegistry iconRegistry;

    private final JPanel unifiedStatusPanel;
    private final JLabel logoLabel;
    private final JLabel unifiedStatusLabel;
    private final JProgressBar unifiedProgressBar;
    private final JLabel unifiedProgressLabel;
    private final JButton initialUploadButton;
    private final JButton rerunButton;
    private final JLabel warningIconLabel;

    public StatusBarComponent(PluginTool tool,
            StatusBarViewModel viewModel,
            StatusBarActions actions,
            IconRegistry iconRegistry) {
        super(new BorderLayout());
        this.viewModel = viewModel;
        this.actions = actions;
        this.iconRegistry = iconRegistry;

        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        unifiedStatusPanel = new JPanel();
        unifiedStatusPanel.setLayout(new BoxLayout(unifiedStatusPanel, BoxLayout.X_AXIS));
        unifiedStatusPanel.setOpaque(false);
        unifiedStatusPanel.setMinimumSize(new Dimension(200, PANEL_HEIGHT));
        unifiedStatusPanel.setPreferredSize(new Dimension(400, PANEL_HEIGHT));

        logoLabel = new JLabel();
        logoLabel.setAlignmentY(Component.CENTER_ALIGNMENT);
        setIcon(logoLabel, "icons/zenyard_icon.png", "Z");
        unifiedStatusPanel.add(logoLabel);

        initialUploadButton = new JButton();
        initialUploadButton.setToolTipText("Click to analyze with Zenyard");
        initialUploadButton.setAlignmentY(Component.CENTER_ALIGNMENT);
        initialUploadButton.setVisible(false);
        setIcon(initialUploadButton, "icons/upload_icon.png", "Upload");
        initialUploadButton.addActionListener(event -> {
            if (actions != null) {
                actions.onInitialUpload();
            }
        });

        unifiedStatusPanel.add(Box.createHorizontalStrut(SPACING_SMALL));
        unifiedStatusPanel.add(initialUploadButton);

        rerunButton = new JButton();
        rerunButton.setToolTipText("Rerun analysis");
        rerunButton.setAlignmentY(Component.CENTER_ALIGNMENT);
        rerunButton.setVisible(false);
        setIcon(rerunButton, "icons/save_results_icon.png", "Rerun");
        rerunButton.addActionListener(event -> {
            if (actions != null) {
                actions.onRerun();
            }
        });

        unifiedStatusPanel.add(Box.createHorizontalStrut(SPACING_SMALL));
        unifiedStatusPanel.add(rerunButton);
        unifiedStatusPanel.add(Box.createHorizontalStrut(SPACING_MEDIUM));

        warningIconLabel = new JLabel();
        warningIconLabel.setToolTipText("Can't reach server");
        warningIconLabel.setAlignmentY(Component.CENTER_ALIGNMENT);
        warningIconLabel.setVisible(false);
        setIcon(warningIconLabel, "icons/warning_icon.png", "!");
        unifiedStatusPanel.add(warningIconLabel);
        unifiedStatusPanel.add(Box.createHorizontalStrut(SPACING_MEDIUM));

        unifiedStatusLabel = new GDLabel("");
        unifiedStatusLabel.setAlignmentY(Component.CENTER_ALIGNMENT);
        unifiedStatusPanel.add(unifiedStatusLabel);
        unifiedStatusPanel.add(Box.createHorizontalStrut(SPACING_MEDIUM));

        unifiedProgressBar = new JProgressBar(0, 100);
        unifiedProgressBar.setStringPainted(false);
        unifiedProgressBar.setAlignmentY(Component.CENTER_ALIGNMENT);
        unifiedProgressBar.setPreferredSize(new Dimension(PROGRESS_WIDTH, 18));
        unifiedProgressBar.setVisible(false);
        unifiedStatusPanel.add(unifiedProgressBar);
        unifiedStatusPanel.add(Box.createHorizontalStrut(SPACING_SMALL));

        unifiedProgressLabel = new GDLabel("");
        unifiedProgressLabel.setAlignmentY(Component.CENTER_ALIGNMENT);
        unifiedProgressLabel.setVisible(false);
        unifiedStatusPanel.add(unifiedProgressLabel);

        unifiedStatusPanel.setVisible(true);
        add(unifiedStatusPanel, BorderLayout.CENTER);

        if (this.viewModel != null) {
            this.viewModel.addListener(this::updateStatus);
            updateStatus(this.viewModel.getStateSnapshot());
        }
    }

    public JPanel getUnifiedStatusPanel() {
        return unifiedStatusPanel;
    }

    private void updateStatus(StatusBarState state) {
        if (state == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            unifiedStatusLabel.setText(state.getStatus() != null ? state.getStatus() : "");

            Integer progress = state.getProgress();
            if (state.isIndeterminate()) {
                unifiedProgressLabel.setVisible(false);
                unifiedProgressBar.setIndeterminate(true);
                unifiedProgressBar.setVisible(true);
            } else if (progress != null) {
                unifiedProgressBar.setIndeterminate(false);
                unifiedProgressBar.setValue(progress);
                unifiedProgressBar.setVisible(true);
                unifiedProgressLabel.setText(progress + "%");
                unifiedProgressLabel.setVisible(true);
            } else {
                unifiedProgressBar.setVisible(false);
                unifiedProgressLabel.setVisible(false);
            }

            initialUploadButton.setVisible(state.isShowInitialUpload());
            rerunButton.setVisible(state.isShowRerun());
            warningIconLabel.setVisible(state.isShowWarningIcon());
            unifiedStatusPanel.revalidate();
            unifiedStatusPanel.repaint();
        });
    }

    private void setIcon(JLabel label, String resourcePath, String fallbackText) {
        if (iconRegistry == null) {
            label.setText(fallbackText);
            return;
        }
        Icon icon = iconRegistry.loadIcon(resourcePath, ICON_SIZE, ICON_SIZE, fallbackText);
        if (icon != null) {
            label.setIcon(icon);
            label.setText("");
        } else {
            label.setText(fallbackText);
        }
    }

    private void setIcon(JButton button, String resourcePath, String fallbackText) {
        if (iconRegistry == null) {
            button.setText(fallbackText);
            return;
        }
        Icon icon = iconRegistry.loadIcon(resourcePath, ICON_SIZE, ICON_SIZE, fallbackText);
        if (icon != null) {
            button.setIcon(icon);
            button.setText("");
        } else {
            button.setText(fallbackText);
        }
    }
}
