package com.zenyard.ghidra.ui;

import java.awt.BorderLayout;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

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
        super("Binary Size Limit Exceeded", true);
        this.maxSizeMb = maxSizeMb;
        buildPanel();
    }

    private void buildPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(createTitlePanel("Binary Size Limit Exceeded"), BorderLayout.NORTH);

        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(12, 12, 12, 12));

        String message = "<html>The demo version of Zenyard supports binaries up to "
            + maxSizeMb
            + "MB (full versions have no limit).<br><br>"
            + "This binary exceeds the limit, so Zenyard has been disabled for this database.</html>";
        mainPanel.add(new JLabel(message), BorderLayout.CENTER);

        contentPanel.add(mainPanel, BorderLayout.CENTER);
        addWorkPanel(contentPanel);
        addOKButton();
    }

    @Override
    protected void okCallback() {
        close();
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
