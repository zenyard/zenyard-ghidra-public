package com.zenyard.decompai.ghidra.illum;

import java.awt.Color;
import java.awt.Component;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.tree.TreeCellRenderer;

import docking.ComponentProvider;
import docking.DockingWindowManager;
import ghidra.app.plugin.core.symboltree.SymbolGTree;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import docking.widgets.tree.support.GTreeRenderer;

/**
 * Highlights renamed functions in the Symbol Tree by coloring their node background.
 */
public final class SymbolTreeHighlighter {
    private static final Color RENAMED_FUNCTION_BACKGROUND = new Color(0xEA, 0xD1, 0xDC);
    private static final String SYMBOL_TREE_PROVIDER_CLASS =
        "ghidra.app.plugin.core.symboltree.SymbolTreeProvider";
    private static final String SYMBOL_TREE_PROVIDER_NAME = "Symbol Tree";

    private SymbolTreeHighlighter() {
    }

    public static void installRenderer(PluginTool tool) {
        if (tool == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            Msg.debug(SymbolTreeHighlighter.class, "Installing Symbol Tree renderer");
            ComponentProvider namedProvider = tool.getComponentProvider(SYMBOL_TREE_PROVIDER_NAME);
            if (namedProvider != null) {
                Msg.debug(SymbolTreeHighlighter.class, "Found provider by name: " + SYMBOL_TREE_PROVIDER_NAME);
                installRendererForProvider(namedProvider);
            }

            DockingWindowManager windowManager = DockingWindowManager.getInstance(tool.getToolFrame());
            if (windowManager == null) {
                windowManager = DockingWindowManager.getActiveInstance();
            }
            if (windowManager == null) {
                Msg.debug(SymbolTreeHighlighter.class, "No active DockingWindowManager");
                return;
            }
            List<ComponentProvider> providers = windowManager.getComponentProviders(ComponentProvider.class);
            for (ComponentProvider provider : providers) {
                if (!SYMBOL_TREE_PROVIDER_CLASS.equals(provider.getClass().getName())) {
                    continue;
                }
                Msg.debug(SymbolTreeHighlighter.class, "Found SymbolTreeProvider instance");
                installRendererForProvider(provider);
            }
        });
    }

    private static void installRendererForProvider(ComponentProvider provider) {
        SymbolGTree tree = findSymbolTree(provider.getComponent());
        if (tree == null) {
            Msg.debug(SymbolTreeHighlighter.class, "No SymbolGTree found for provider");
            return;
        }
        TreeCellRenderer currentRenderer = tree.getCellRenderer();
        if (currentRenderer instanceof RenamedSymbolTreeRenderer) {
            return;
        }
        tree.setCellRenderer(new RenamedSymbolTreeRenderer(currentRenderer));
        tree.repaint();
        Msg.debug(SymbolTreeHighlighter.class, "Installed renamed-symbol tree renderer");
    }

    private static SymbolGTree findSymbolTree(Component component) {
        if (component instanceof SymbolGTree) {
            return (SymbolGTree) component;
        }
        if (component instanceof JComponent) {
            for (Component child : ((JComponent) component).getComponents()) {
                SymbolGTree tree = findSymbolTree(child);
                if (tree != null) {
                    return tree;
                }
            }
        }
        return null;
    }

    private static boolean hasRenamedTag(Function function) {
        return function.getTags().stream()
            .anyMatch(tag -> FunctionListHighlighter.RENAMED_FUNCTION_TAG.equals(tag.getName()));
    }

    private static final class RenamedSymbolTreeRenderer extends GTreeRenderer {
        private final TreeCellRenderer delegate;

        private RenamedSymbolTreeRenderer(TreeCellRenderer delegate) {
            this.delegate = delegate;
        }

        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected,
                boolean expanded, boolean leaf, int row, boolean hasFocus) {
            Component renderer = delegate.getTreeCellRendererComponent(
                tree, value, selected, expanded, leaf, row, hasFocus);

            if (value instanceof SymbolNode) {
                Symbol symbol = ((SymbolNode) value).getSymbol();
                if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
                    Object obj = symbol.getObject();
                    if (obj instanceof Function && hasRenamedTag((Function) obj)) {
                        if (renderer instanceof JComponent) {
                            ((JComponent) renderer).setOpaque(true);
                        }
                        if (selected) {
                            renderer.setBackground(blend(getSelectionBackground(tree), RENAMED_FUNCTION_BACKGROUND, 0.6f));
                        } else {
                            renderer.setBackground(RENAMED_FUNCTION_BACKGROUND);
                        }
                        return renderer;
                    }
                }
            }

            if (renderer instanceof JComponent) {
                ((JComponent) renderer).setOpaque(false);
            }
            renderer.setBackground(tree.getBackground());
            return renderer;
        }
    }

    private static Color blend(Color base, Color overlay, float overlayRatio) {
        if (base == null) {
            return overlay;
        }
        float clamped = Math.max(0f, Math.min(1f, overlayRatio));
        int r = Math.round(base.getRed() * (1f - clamped) + overlay.getRed() * clamped);
        int g = Math.round(base.getGreen() * (1f - clamped) + overlay.getGreen() * clamped);
        int b = Math.round(base.getBlue() * (1f - clamped) + overlay.getBlue() * clamped);
        return new Color(r, g, b);
    }

    private static Color getSelectionBackground(JTree tree) {
        Color selection = UIManager.getColor("Tree.selectionBackground");
        return selection != null ? selection : tree.getBackground();
    }
}
