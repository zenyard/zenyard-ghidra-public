package com.zenyard.decompai.ghidra.status;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.awt.Image;
import java.awt.Component;
import java.io.InputStream;

import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;

import docking.widgets.label.GDLabel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.HashSet;
import java.util.Set;

import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.events.EventConsumer;
import com.zenyard.decompai.ghidra.events.EventDispatcher;
import com.zenyard.decompai.ghidra.upload.QueueRevisionsTask;
import com.zenyard.decompai.ghidra.DecompaiServices;
import com.zenyard.decompai.ghidra.DecompaiGhidraPlugin;
import com.zenyard.decompai.ghidra.upload.UploadRevisionsTask;
import com.zenyard.decompai.ghidra.api.generated.api.BinariesApi;

/**
 * Status bar component that displays DecompAI status and provides a button
 * to rerun analysis. Includes unified status display with logo, task status, and progress.
 * Subscribes to CHANGES_DETECTED events to update UI.
 * 
 * NOTE: mirrors functionality in decompai_ida/status_bar_widget.py
 */
public class DecompaiStatusBarComponent extends JPanel implements EventConsumer {
    
    private final PluginTool tool;
// private final JLabel statusLabel;
    private JButton rerunButton; // Initialized in createUnifiedStatusPanel()
    // private final JProgressBar busyIndicator;
    private EventDispatcher eventDispatcher;
    
    // Unified status display panel (for status bar integration)
    private final JPanel unifiedStatusPanel;
    private JLabel logoLabel;
    private JLabel unifiedStatusLabel;
    private JProgressBar unifiedProgressBar;
    private JLabel unifiedProgressLabel; // For percentage display
    private JLabel loadingAnimationLabel; // Animated loading indicator (image-based)
    
    public DecompaiStatusBarComponent(PluginTool tool) {
        super(new BorderLayout());
        this.tool = tool;
        
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // Main panel with vertical layout
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.X_AXIS));
        
        // Top row: status label and buttons
        JPanel topRow = new JPanel(new BorderLayout());
        topRow.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
        
        // Status label
        // statusLabel = new GDLabel("DecompAI: Ready");
        // topRow.add(statusLabel, BorderLayout.CENTER);
        
        // // Busy indicator (spinner)
        // busyIndicator = new JProgressBar();
        // busyIndicator.setIndeterminate(false);
        // busyIndicator.setStringPainted(false);
        // busyIndicator.setVisible(false);
        // busyIndicator.setPreferredSize(new Dimension(20, 18));
        // topRow.add(busyIndicator, BorderLayout.WEST);
        
        mainPanel.add(topRow);
        
        // Unified status panel for status bar integration
        // Initialize fields first
        logoLabel = new JLabel();
        unifiedStatusLabel = new GDLabel("");
        unifiedProgressBar = new JProgressBar(0, 100);
        unifiedProgressLabel = new GDLabel("");
        
        unifiedStatusPanel = createUnifiedStatusPanel();
        // Make panel visible by default (will be shown/hidden based on active tasks)
        unifiedStatusPanel.setVisible(true);
                
        add(mainPanel, BorderLayout.CENTER);
    }
    
    /**
     * Set the event dispatcher and subscribe to CHANGES_DETECTED events.
     */
    public void setEventDispatcher(EventDispatcher eventDispatcher) {
        // Unsubscribe from old dispatcher if any
        if (this.eventDispatcher != null) {
            this.eventDispatcher.unsubscribe(this);
            Msg.debug(this, "Unsubscribed DecompaiStatusBarComponent from old event dispatcher");
        }
        
        this.eventDispatcher = eventDispatcher;
        
        // Subscribe to events
        if (this.eventDispatcher != null) {
            this.eventDispatcher.subscribe(this);
            Msg.info(this, "DecompaiStatusBarComponent subscribed to CHANGES_DETECTED events");
        } else {
            Msg.warn(this, "DecompaiStatusBarComponent: eventDispatcher is null, cannot subscribe");
        }
    }
    
    @Override
    public Set<DecompaiEvent.EventType> getSubscribedEventTypes() {
        Set<DecompaiEvent.EventType> types = new HashSet<>();
        types.add(DecompaiEvent.EventType.CHANGES_DETECTED);
        return types;
    }
    
    @Override
    public void handleEvent(DecompaiEvent event) {
        if (event.getType() == DecompaiEvent.EventType.CHANGES_DETECTED) {
            // Update UI on EDT
            SwingUtilities.invokeLater(() -> {
                toggleRerunButtonVisible(true);
                updateUnifiedStatus("Updates detected — Click to analyze", null, false);
            });
        }
    }
    
    /**
     * Create unified status panel with logo, status, and progress indicator.
     * Structure: [Zenyard Logo] | <Task Status> | [Progress Indicator]
     * Uses horizontal BoxLayout for proper spacing and vertical alignment.
     */
    private JPanel createUnifiedStatusPanel() {
        // Use BoxLayout for horizontal layout - ensures proper spacing
        JPanel panel = new JPanel();
        BoxLayout layout = new BoxLayout(panel, BoxLayout.X_AXIS);
        panel.setLayout(layout);
        panel.setOpaque(false);
        // Set minimum size to ensure panel is visible - make it smaller since we have button
        panel.setMinimumSize(new Dimension(200, 25));
        panel.setPreferredSize(new Dimension(400, 25));
        
        // Zenyard logo (already initialized)
        logoLabel = new JLabel();
        logoLabel.setAlignmentY(Component.CENTER_ALIGNMENT);
        logoLabel.setVisible(true); // Ensure it's visible
        logoLabel.setText(""); // Clear any text to show icon
        
        try {
            // Try loading from resources - use class loader with correct path
            // Resources in src/main/resources are accessible via class loader
            InputStream iconStream = getClass().getClassLoader().getResourceAsStream("icons/zenyard_icon.png");
                        
            if (iconStream != null) {
                try {
                    BufferedImage image = ImageIO.read(iconStream);
                    if (image != null) {
                        // Scale icon to fit (18x18 to match IDA's size)
                        Image scaledImage = image.getScaledInstance(20, 20, Image.SCALE_SMOOTH);
                        ImageIcon icon = new ImageIcon(scaledImage);
                        logoLabel.setIcon(icon);
                        logoLabel.setText(""); // Clear text to ensure icon shows
                        logoLabel.setToolTipText("Zenyard");
                    } else {
                        logoLabel.setText("Z");
                    }
                } catch (Exception e) {
                    Msg.warn(this, "Error reading icon image: " + e.getMessage(), e);
                    logoLabel.setText("Z");
                } finally {
                    iconStream.close();
                }
            } 
        } catch (Exception e) {
            logoLabel.setText("Z");
            Msg.warn(this, "Could not load Zenyard icon: " + e.getMessage(), e);
        }
        panel.add(logoLabel);
        
        // Rerun button (always visible) - positioned right next to the logo
        // Use icon button like in IDA (save_results_icon.png)
        rerunButton = new JButton();
        rerunButton.setToolTipText("Rerun analysis");
        rerunButton.setVisible(false);
        rerunButton.setAlignmentY(Component.CENTER_ALIGNMENT);
        rerunButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                onRerunClicked();
            }
        });
        
        // Load save_results_icon.png (same as IDA)
        try {
            InputStream iconStream = getClass().getClassLoader().getResourceAsStream("icons/save_results_icon.png");
            if (iconStream != null) {
                try {
                    BufferedImage image = ImageIO.read(iconStream);
                    if (image != null) {
                        Image scaledImage = image.getScaledInstance(20, 20, Image.SCALE_SMOOTH);
                        ImageIcon icon = new ImageIcon(scaledImage);
                        rerunButton.setIcon(icon);
                        rerunButton.setText(""); // Clear text to show icon only
                    }
                } catch (Exception e) {
                    Msg.warn(this, "Error reading save_results icon: " + e.getMessage(), e);
                    rerunButton.setText("Rerun");
                } finally {
                    iconStream.close();
                }
            } else {
                rerunButton.setText("Rerun");
            }
        } catch (Exception e) {
            Msg.warn(this, "Could not load save_results icon: " + e.getMessage(), e);
            rerunButton.setText("Rerun");
        }
        
        panel.add(Box.createHorizontalStrut(4)); // Small spacing between logo and button
        panel.add(rerunButton);
        panel.add(Box.createHorizontalStrut(8)); // Fixed 8px spacing after button
        
        // Task status label
        unifiedStatusLabel = new GDLabel("");
        unifiedStatusLabel.setAlignmentY(Component.CENTER_ALIGNMENT);
        panel.add(unifiedStatusLabel);
        panel.add(Box.createHorizontalStrut(8));
        
        unifiedProgressBar.setStringPainted(false);
        unifiedProgressBar.setAlignmentY(Component.CENTER_ALIGNMENT);
        unifiedProgressBar.setPreferredSize(new Dimension(100, 18));
        unifiedProgressBar.setVisible(false); // Initially hidden, shown when progress is available
        panel.add(unifiedProgressBar);
        panel.add(Box.createHorizontalStrut(4)); // Fixed 4px spacing between bar and label
        
        unifiedProgressLabel.setAlignmentY(Component.CENTER_ALIGNMENT);
        unifiedProgressLabel.setVisible(false); // Initially hidden, shown when progress is available
        panel.add(unifiedProgressLabel);
                
        // Ensure panel and all components are visible and properly configured
        panel.setVisible(true);
        panel.validate();
                
        return panel;
    }
        
    /**
     * Get the unified status panel for status bar integration.
     */
    public JPanel getUnifiedStatusPanel() {
        return unifiedStatusPanel;
    }
    
    /**
     * Update unified status display.
     * @param status Status message
     * @param progress Progress value (0-100) or null for indeterminate
     * @param indeterminate Whether to show indeterminate progress
     */
    public void updateUnifiedStatus(String status, Integer progress, boolean indeterminate) {
        SwingUtilities.invokeLater(() -> {
            // Ensure unified status panel is visible
            if (unifiedStatusPanel != null) {
                unifiedStatusPanel.setVisible(true);
            }
            
            // Ensure logo is always visible when panel is shown
            if (logoLabel != null) {
                logoLabel.setVisible(true);
                // Ensure icon is visible (not just text)
                if (logoLabel.getIcon() != null) {
                    logoLabel.setText(""); // Clear any text to show icon
                }
            }
            
            unifiedStatusLabel.setText(status != null ? status : "");
            unifiedStatusLabel.setVisible(true);
            
            if (indeterminate) {
                // Show loading animation instead of indeterminate progress bar
                unifiedProgressLabel.setVisible(false);
                unifiedProgressBar.setIndeterminate(true);
                unifiedProgressBar.setVisible(true);
                Msg.debug(this, "Showing indeterminate progress bar");
            } else if (progress != null && progress >= 0 && progress <= 100) {
                // Show progress bar with percentage
                unifiedProgressBar.setIndeterminate(false);
                unifiedProgressBar.setValue(progress);
                unifiedProgressBar.setVisible(true);
                
                // Show percentage label next to progress bar
                unifiedProgressLabel.setText(progress + "%");
                unifiedProgressLabel.setVisible(true);
            } else {
                // No progress info - just show status
                unifiedProgressBar.setVisible(false);
                unifiedProgressLabel.setVisible(false);
                if (loadingAnimationLabel != null) {
                    loadingAnimationLabel.setVisible(false);
                }
            }
            
            // Force repaint to ensure visibility
            if (unifiedStatusPanel != null) {
                unifiedStatusPanel.revalidate();
                unifiedStatusPanel.repaint();
            }
        });
    }
                    
    public void toggleRerunButtonVisible(boolean visible) {
        SwingUtilities.invokeLater(() -> {
            if (rerunButton != null) {
                rerunButton.setVisible(visible);
                rerunButton.repaint();
            }
        });
    }
    
    /**
     * Handle rerun button click.
     */
    private void onRerunClicked() {
        // Get current program from singleton services
        Program program = DecompaiServices.getProgram();
        DecompaiServices services = DecompaiServices.getInstance();

        // Get required services
        StatusBarManager statusBarManager = services.getStatusBarManager();
        EventDispatcher eventDispatcher = services.getEventDispatcher();
                
        QueueRevisionsTask queueRevisionsTask = new QueueRevisionsTask(
            tool, program, statusBarManager, eventDispatcher, true);
        DecompaiGhidraPlugin.executeBackgroundTask(queueRevisionsTask);

        BinariesApi binariesApi = services.getBinariesApi();

        // Start UploadRevisionsTask to listen for REVISIONS_QUEUED event and upload
        UploadRevisionsTask uploadRevisionsTask = new UploadRevisionsTask(
            tool, binariesApi, statusBarManager, program, eventDispatcher);
        DecompaiGhidraPlugin.executeBackgroundTask(uploadRevisionsTask);

        toggleRerunButtonVisible(false);
    }
}
