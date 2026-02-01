package com.zenyard.ghidra.ui;

import docking.DialogComponentProvider;
import docking.widgets.label.GDLabel;
import resources.ResourceManager;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.Image;

public class ZenyardDialogComponentProvider extends DialogComponentProvider {
    private static final int LOGO_MAX_SIZE_PX = 32;

    public ZenyardDialogComponentProvider(String title, boolean isModal) {
        super(title, isModal);
    }

    public ZenyardDialogComponentProvider(String title, boolean isModal, boolean hasHelp,
                                          boolean hasStatus, boolean hasToolBar) {
        super(title, isModal, hasHelp, hasStatus, hasToolBar);
    }

    protected JPanel createTitlePanel(String title) {
        Icon dialogIcon = null;
        try {
            dialogIcon = ResourceManager.loadImage("icons/zenyard_icon.png");
        } catch (Exception e) {
            // If loading fails, fall back to no icon
        }
        if (dialogIcon instanceof ImageIcon) {
            ImageIcon imageIcon = (ImageIcon) dialogIcon;
            dialogIcon = scaleIcon(imageIcon, LOGO_MAX_SIZE_PX);
        }

        JLabel titleLabel = new GDLabel(title);
        Font currentFont = titleLabel.getFont();
        titleLabel.setFont(currentFont.deriveFont(Font.BOLD));

        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createEtchedBorder(),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        if (dialogIcon != null) {
            JLabel iconLabel = new JLabel(dialogIcon);
            titlePanel.add(iconLabel, BorderLayout.WEST);
        }

        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.X_AXIS));
        centerPanel.add(Box.createHorizontalGlue());
        centerPanel.add(titleLabel);
        centerPanel.add(Box.createHorizontalGlue());

        titlePanel.add(centerPanel, BorderLayout.CENTER);

        return titlePanel;
    }

    private ImageIcon scaleIcon(ImageIcon icon, int maxSizePx) {
        int width = icon.getIconWidth();
        int height = icon.getIconHeight();
        if (width <= 0 || height <= 0) {
            return icon;
        }
        if (width <= maxSizePx && height <= maxSizePx) {
            return icon;
        }

        double scale = Math.min((double) maxSizePx / width, (double) maxSizePx / height);
        int targetWidth = (int) Math.round(width * scale);
        int targetHeight = (int) Math.round(height * scale);
        Image scaledImage = icon.getImage().getScaledInstance(targetWidth, targetHeight, Image.SCALE_SMOOTH);
        return new ImageIcon(scaledImage);
    }
}
