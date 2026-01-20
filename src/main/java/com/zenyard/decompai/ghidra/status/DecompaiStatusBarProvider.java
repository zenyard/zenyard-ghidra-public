package com.zenyard.decompai.ghidra.status;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;

/**
 * Component provider for DecompAI status bar component.
 * This allows the status bar component to be displayed in Ghidra's UI.
 */
public class DecompaiStatusBarProvider extends ComponentProvider {
    
    private final DecompaiStatusBarComponent component;
    
    public DecompaiStatusBarProvider(PluginTool tool, DecompaiStatusBarComponent component) {
        super(tool, "DecompAI Status", "DecompAI");
        this.component = component;
    }
    
    @Override
    public javax.swing.JComponent getComponent() {
        return component;
    }
}

