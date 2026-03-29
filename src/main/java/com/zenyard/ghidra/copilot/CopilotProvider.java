package com.zenyard.ghidra.copilot;

import java.awt.BorderLayout;
import java.awt.KeyboardFocusManager;
import java.awt.event.KeyEvent;
import java.lang.reflect.Field;

import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.ComponentProvider;
import docking.WindowPosition;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import com.zenyard.ghidra.ZenyardService;
import com.zenyard.ghidra.events.ZenyardEvent;

/**
 * A ComponentProvider dockable window implementing the Copilot chat UI.
 * 
 * NOTE: mirrors functionality in zenyard_ida/ui/copilot.py
 */
public class CopilotProvider extends ComponentProvider {

    private CopilotController controller;
    private CopilotViewModel viewModel;
    private CopilotWebViewPanel webViewPanel;
    private final java.awt.KeyEventDispatcher copilotKeyDispatcher = this::dispatchCopilotKeyEvent;
    private boolean keyHandlersInstalled;
    private java.awt.KeyEventDispatcher ghidraKeyDispatcher;
    
    public CopilotProvider(PluginTool tool, CopilotController controller) {
        super(tool, "", "Zenyard");
        this.controller = controller;
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        setWindowGroup("Console");
        setIntraGroupPosition(WindowPosition.STACK);
        
        buildComponent();
    }
    
    public void setController(CopilotController controller) {
        this.controller = controller;
        if (webViewPanel != null) {
            webViewPanel.setController(controller);
        }
        Msg.info(this, "CopilotProvider controller set: " + (controller != null));
    }

    public void setViewModel(CopilotViewModel viewModel) {
        this.viewModel = viewModel;
        if (webViewPanel != null) {
            webViewPanel.setViewModel(viewModel);
        }
    }

    /**
     * Refresh the Copilot UI state (e.g. when usage state changes).
     */
    public void refreshState() {
        if (webViewPanel != null) {
            webViewPanel.refreshState();
        }
    }

    private void buildComponent() {
        JPanel mainPanel = new JPanel(new BorderLayout());

        try {
            webViewPanel = new CopilotWebViewPanel();
            webViewPanel.setController(controller);
            if (viewModel != null) {
                webViewPanel.setViewModel(viewModel);
            }
            mainPanel.add(webViewPanel, BorderLayout.CENTER);
        } catch (Throwable t) {
            // If JavaFX fails to initialize (missing/incorrect natives, missing GTK libs, etc),
            // keep the extension functional and show a clear message instead of crashing plugin activation.
            Msg.error(this, "Copilot UI failed to initialize (JavaFX WebView unavailable): " + t.getMessage(), t);
            JPanel fallback = new JPanel(new BorderLayout());
            String message = "<html><center><b>Copilot UI unavailable</b></center><br>"
                    + "JavaFX WebView could not be initialized on this system.<br><br>"
                    + "If you are on Linux x64, ensure the extension ZIP was built with<br>"
                    + "<code>-PjavafxPlatform=linux</code> and that GTK dependencies are installed.<br><br>"
                    + (t.getMessage() != null ? "<small>" + t.getMessage() + "</small>" : "")
                    + "</html>";
            fallback.add(new JLabel(message), BorderLayout.CENTER);
            mainPanel.add(fallback, BorderLayout.CENTER);
        }
        
        // In Ghidra 12.0, ComponentProvider may require getComponent() method
        // Store component and provide getComponent() implementation
        this.component = mainPanel;
    }
    
    private JPanel component;
    
    // In Ghidra 12.0, ComponentProvider requires getComponent() method returning JComponent
    @Override
    public javax.swing.JComponent getComponent() {
        return component;
    }
    
    public void appendMessage(String message) {
        if (viewModel != null) {
            viewModel.addMessage(message, false);
            return;
        }
        Msg.warn(this, "Copilot message: " + message);
    }
    
    @Override
    public void componentShown() {
        installKeyHandlers();
        ZenyardService svc = ZenyardService.getInstanceForTool((PluginTool) getTool());
        if (svc != null) {
            svc.getEventDispatcher().publish(
                new ZenyardEvent(ZenyardEvent.EventType.COPILOT_OPENED, "CopilotProvider"));
        }
    }
    
    @Override
    public void componentHidden() {
        removeKeyHandlers();
    }

    private void installKeyHandlers() {
        if (keyHandlersInstalled) {
            return;
        }
        KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
        ghidraKeyDispatcher = findGhidraKeyDispatcher();
        if (ghidraKeyDispatcher != null) {
            kfm.removeKeyEventDispatcher(ghidraKeyDispatcher);
        }
        kfm.addKeyEventDispatcher(copilotKeyDispatcher);
        if (ghidraKeyDispatcher != null) {
            kfm.addKeyEventDispatcher(ghidraKeyDispatcher);
        }
        keyHandlersInstalled = true;
    }

    private void removeKeyHandlers() {
        if (!keyHandlersInstalled) {
            return;
        }
        KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
        kfm.removeKeyEventDispatcher(copilotKeyDispatcher);
        if (ghidraKeyDispatcher != null) {
            kfm.removeKeyEventDispatcher(ghidraKeyDispatcher);
            kfm.addKeyEventDispatcher(ghidraKeyDispatcher);
        }
        keyHandlersInstalled = false;
    }

    private boolean dispatchCopilotKeyEvent(KeyEvent event) {
        if (webViewPanel == null || !webViewPanel.isFocusWithin()) {
            return false;
        }
        webViewPanel.redispatchKeyEvent(event);
        event.consume();
        return true;
    }

    private java.awt.KeyEventDispatcher findGhidraKeyDispatcher() {
        try {
            Class<?> clazz = Class.forName("docking.KeyBindingOverrideKeyEventDispatcher");
            Field instanceField = clazz.getDeclaredField("instance");
            instanceField.setAccessible(true);
            Object instance = instanceField.get(null);
            if (instance instanceof java.awt.KeyEventDispatcher) {
                return (java.awt.KeyEventDispatcher) instance;
            }
        } catch (ReflectiveOperationException e) {
            Msg.debug(this, "Failed to locate Ghidra key dispatcher: " + e.getMessage());
        }
        return null;
    }
}

