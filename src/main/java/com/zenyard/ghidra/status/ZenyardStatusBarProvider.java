package com.zenyard.ghidra.status;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;

/**
 * Component provider for Zenyard status bar component.
 * This allows the status bar component to be displayed in Ghidra's UI.
 */
public class ZenyardStatusBarProvider extends ComponentProvider {
    
    private final StatusBarComponent component;
    
    public ZenyardStatusBarProvider(PluginTool tool, StatusBarComponent component) {
        super(tool, "Zenyard Status", "Zenyard");
        this.component = component;
    }
    
    @Override
    public javax.swing.JComponent getComponent() {
        return component;
    }
}

