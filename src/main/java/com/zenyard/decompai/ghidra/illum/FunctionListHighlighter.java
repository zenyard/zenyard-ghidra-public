package com.zenyard.decompai.ghidra.illum;

import java.awt.Color;
import java.awt.Component;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.SwingUtilities;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.plugin.core.functionwindow.FunctionRowObject;
import ghidra.app.util.SymbolInspector;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;

/**
 * Highlights renamed functions in the Functions window by coloring their name cell.
 */
public final class FunctionListHighlighter {
    public static final String RENAMED_FUNCTION_TAG = "DecompAI Renamed";
    private static final Color RENAMED_FUNCTION_BACKGROUND = new Color(0xEA, 0xD1, 0xDC);
    private static final String FUNCTION_WINDOW_PROVIDER_CLASS =
        "ghidra.app.plugin.core.functionwindow.FunctionWindowProvider";
    private static final String FUNCTION_WINDOW_PROVIDER_NAME = "Functions Window";
    private static final String FUNCTION_NAME_COLUMN = "Name";

    private FunctionListHighlighter() {
    }

    public static void markFunctionRenamed(Function function) {
        if (function == null) {
            return;
        }
        try {
            function.addTag(RENAMED_FUNCTION_TAG);
        } catch (Exception e) {
            Msg.debug(FunctionListHighlighter.class, "Failed to tag renamed function: " + e.getMessage());
        }
    }

    public static void installRenderer(PluginTool tool) {
        if (tool == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            Msg.debug(FunctionListHighlighter.class, "Installing Functions window renderer");
            DockingWindowManager windowManager = DockingWindowManager.getInstance(tool.getToolFrame());
            if (windowManager == null) {
                windowManager = DockingWindowManager.getActiveInstance();
            }
            ComponentProvider namedProvider = tool.getComponentProvider(FUNCTION_WINDOW_PROVIDER_NAME);
            if (namedProvider != null) {
                Msg.debug(FunctionListHighlighter.class, "Found provider by name: " + FUNCTION_WINDOW_PROVIDER_NAME);
                installRendererForProvider(tool, namedProvider);
            }
            if (windowManager == null) {
                Msg.debug(FunctionListHighlighter.class, "No active DockingWindowManager");
                return;
            }
            List<ComponentProvider> providers = windowManager.getComponentProviders(ComponentProvider.class);
            for (ComponentProvider provider : providers) {
                if (!FUNCTION_WINDOW_PROVIDER_CLASS.equals(provider.getClass().getName())) {
                    continue;
                }
                Msg.debug(FunctionListHighlighter.class, "Found FunctionWindowProvider instance");
                installRendererForProvider(tool, provider);
            }
        });
    }

    private static void installRendererForProvider(PluginTool tool, ComponentProvider provider) {
        GhidraTable table = findTable(provider.getComponent());
        if (table == null) {
            Msg.debug(FunctionListHighlighter.class, "No GhidraTable found for provider");
            return;
        }
        TableColumn nameColumn = findNameColumn(table.getColumnModel());
        if (nameColumn == null) {
            Msg.debug(FunctionListHighlighter.class, "No Name column found in Functions table");
            return;
        }
        if (!(nameColumn.getCellRenderer() instanceof RenamedFunctionNameRenderer)) {
            nameColumn.setCellRenderer(new RenamedFunctionNameRenderer(tool));
            Msg.debug(FunctionListHighlighter.class, "Installed renamed-function renderer");
        }
        table.repaint();
    }

    private static TableColumn findNameColumn(TableColumnModel model) {
        for (int i = 0; i < model.getColumnCount(); i++) {
            TableColumn column = model.getColumn(i);
            Object header = column.getHeaderValue();
            if (FUNCTION_NAME_COLUMN.equals(header)) {
                return column;
            }
        }
        return null;
    }

    private static GhidraTable findTable(Component component) {
        if (component instanceof GhidraTable) {
            return (GhidraTable) component;
        }
        if (component instanceof JComponent) {
            for (Component child : ((JComponent) component).getComponents()) {
                GhidraTable table = findTable(child);
                if (table != null) {
                    return table;
                }
            }
        }
        return null;
    }

    private static final class RenamedFunctionNameRenderer extends AbstractGhidraColumnRenderer<String> {
        private final SymbolInspector inspector;

        private RenamedFunctionNameRenderer(PluginTool tool) {
            this.inspector = new SymbolInspector(tool, null);
        }

        @Override
        public Component getTableCellRendererComponent(GTableCellRenderingData data) {
            Component cellRenderer = super.getTableCellRendererComponent(data);
            setBold();
            if (data.isSelected()) {
                return cellRenderer;
            }

            Object rowObject = data.getRowObject();
            if (rowObject instanceof FunctionRowObject) {
                Function function = ((FunctionRowObject) rowObject).getFunction();
                if (function != null && hasRenamedTag(function)) {
                    if (cellRenderer instanceof javax.swing.JComponent) {
                        ((javax.swing.JComponent) cellRenderer).setOpaque(true);
                    }
                    cellRenderer.setBackground(RENAMED_FUNCTION_BACKGROUND);
                    Msg.debug(FunctionListHighlighter.class, "Rendering renamed function: " + function.getName());
                    return cellRenderer;
                }
                Symbol symbol = function != null ? function.getSymbol() : null;
                if (symbol != null) {
                    cellRenderer.setForeground(inspector.getColor(symbol));
                }
            }
            if (cellRenderer instanceof javax.swing.JComponent) {
                ((javax.swing.JComponent) cellRenderer).setOpaque(false);
            }
            cellRenderer.setBackground(data.getTable().getBackground());
            return cellRenderer;
        }

        @Override
        public String getFilterString(String value, Settings settings) {
            return value;
        }
    }

    private static boolean hasRenamedTag(Function function) {
        return function.getTags().stream().anyMatch(tag -> RENAMED_FUNCTION_TAG.equals(tag.getName()));
    }
}
