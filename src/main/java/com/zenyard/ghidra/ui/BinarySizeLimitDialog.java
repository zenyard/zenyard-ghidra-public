package com.zenyard.ghidra.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;

import com.zenyard.ghidra.usage.UsageState;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

/**
 * One-time session dialog shown when the binary exceeds the configured size limit.
 */
public class BinarySizeLimitDialog extends ZenyardDialogComponentProvider {
    private static final Set<String> SHOWN_PROGRAM_KEYS = ConcurrentHashMap.newKeySet();
    private final int maxSizeMb;

    public BinarySizeLimitDialog(int maxSizeMb) {
        super("Oops", true);
        this.maxSizeMb = maxSizeMb;
        buildPanel();
    }

    private void buildPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(createTitlePanel("This Binary Is Over the Free Trial Limit"), BorderLayout.NORTH);

        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(12, 12, 12, 12));

        String message = "Oops, this binary is over the " + maxSizeMb + "MB limit for the Zenyard free trial.\n"
            + "The full version supports larger files with no size limit.\n\n"
            + "Need larger-file support?";
        JTextArea messageArea = new JTextArea(message);
        messageArea.setEditable(false);
        messageArea.setOpaque(false);
        messageArea.setLineWrap(true);
        messageArea.setWrapStyleWord(true);
        messageArea.setBorder(null);
        messageArea.setFocusable(false);
        mainPanel.add(messageArea, BorderLayout.CENTER);

        JPanel contactPanel = new JPanel(new BorderLayout());
        contactPanel.setOpaque(false);
        contactPanel.setBorder(new EmptyBorder(6, 0, 0, 0));
        contactPanel.add(createContactLabel(), BorderLayout.WEST);
        mainPanel.add(contactPanel, BorderLayout.SOUTH);

        contentPanel.add(mainPanel, BorderLayout.CENTER);
        addWorkPanel(contentPanel);
        addOKButton();
    }

    @Override
    protected void okCallback() {
        close();
    }

    private JLabel createContactLabel() {
        if (!UsageState.isContactEmailSupported()) {
            return new JLabel(UsageState.getContactSupportText());
        }
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

    public static void showDialogIfNeeded(PluginTool tool, Program program, int maxSizeMb) {
        if (tool == null || program == null || maxSizeMb <= 0) {
            return;
        }
        String key = resolveProgramKey(program);
        if (!SHOWN_PROGRAM_KEYS.add(key)) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            BinarySizeLimitDialog dialog = new BinarySizeLimitDialog(maxSizeMb);
            tool.showDialog(dialog);
        });
    }

    private static String resolveProgramKey(Program program) {
        DomainFile domainFile = program.getDomainFile();
        if (domainFile != null) {
            String path = domainFile.getPathname();
            if (path != null && !path.isEmpty()) {
                return path;
            }
        }
        String executablePath = program.getExecutablePath();
        if (executablePath != null && !executablePath.isEmpty()) {
            return executablePath;
        }
        return program.getName();
    }
}
