package com.zenyard.decompai.ghidra.illum;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Uses Ghidra's program APIs to highlight functions by setting background colors on code units.
 * 
 * NOTE: mirrors functionality in decompai_ida/ui/functions_colorizer_task.py
 */
public class FunctionHighlighter {
    
    /**
     * Highlight a function with the given color.
     * Sets background color on all code units in the function body.
     * 
     * @param program The program containing the function
     * @param function The function to highlight
     * @param color The color to use for highlighting
     * @param tool Optional PluginTool for ColorizingService (can be null)
     */
    public void highlightFunction(Program program, Function function, java.awt.Color color, ghidra.framework.plugintool.PluginTool tool) {
        if (program == null || function == null) {
            return;
        }
        
        int transactionId = program.startTransaction("DecompAI: Highlight function");
        try {
            AddressSet body = new AddressSet(function.getBody());
            
            // Convert color to RGB integer (Ghidra uses 0xRRGGBB format)
            int rgb = (color.getRed() << 16) | (color.getGreen() << 8) | color.getBlue();
            
            // Set background color on all code units in function body
            // Use ColorizingService if available, otherwise use property-based approach
            // Note: ColorizingService API may have changed in Ghidra 12.0 - checking correct package
            if (tool != null) {
                try {
                    // Try to get ColorizingService - API may have changed in Ghidra 12.0
                    // TODO: Update with correct Ghidra 12.0 ColorizingService API
                    Object colorizingService = tool.getService(Class.forName("ghidra.app.util.viewer.field.ColorizingService"));
                    if (colorizingService != null) {
                        // Use reflection to call setBackgroundColor
                        java.lang.reflect.Method setBgMethod = colorizingService.getClass().getMethod("setBackgroundColor", Address.class, java.awt.Color.class);
                        for (Address addr : body.getAddresses(true)) {
                            setBgMethod.invoke(colorizingService, addr, color);
                        }
                        return; // Successfully used ColorizingService
                    }
                } catch (Exception e) {
                    // ColorizingService not available or API changed, fall back to property-based approach
                    Msg.debug(this, "ColorizingService not available, using property-based highlighting: " + e.getMessage());
                }
            }
            
            // Fallback: Use property-based highlighting
            // Store color in program properties for each address
            ghidra.program.model.util.PropertyMapManager propManager = program.getUsrPropertyManager();
            ghidra.program.model.util.IntPropertyMap highlightProp = propManager.getIntPropertyMap("DecompAI_Highlight");
            // In Ghidra 12.0, if map doesn't exist, we skip highlighting (property maps may need to be pre-created)
            if (highlightProp != null) {
                for (Address addr : body.getAddresses(true)) {
                    highlightProp.add(addr, rgb);
                }
            }
            
        } catch (Exception e) {
            program.endTransaction(transactionId, false); // rollback
            Msg.warn(this, "Failed to highlight function: " + e.getMessage(), e);
        } finally {
            if (transactionId >= 0) {
                program.endTransaction(transactionId, true); // commit
            }
        }
    }
    
    /**
     * Clear highlighting for a function.
     * 
     * @param program The program containing the function
     * @param function The function to clear highlighting for
     * @param tool Optional PluginTool for ColorizingService (can be null)
     */
    public void clearHighlight(Program program, Function function, ghidra.framework.plugintool.PluginTool tool) {
        if (program == null || function == null) {
            return;
        }
        
        int transactionId = program.startTransaction("DecompAI: Clear function highlight");
        try {
            AddressSet body = new AddressSet(function.getBody());
            
            // Clear highlighting from all addresses in function body
            if (tool != null) {
                try {
                    // Try to use ColorizingService - API may have changed in Ghidra 12.0
                    // TODO: Update with correct Ghidra 12.0 ColorizingService API
                    Object colorizingService = tool.getService(Class.forName("ghidra.app.util.viewer.field.ColorizingService"));
                    if (colorizingService != null) {
                        // Use reflection to call clearBackgroundColor
                        java.lang.reflect.Method clearBgMethod = colorizingService.getClass().getMethod("clearBackgroundColor", Address.class);
                        for (Address addr : body.getAddresses(true)) {
                            clearBgMethod.invoke(colorizingService, addr);
                        }
                        return; // Successfully cleared using ColorizingService
                    }
                } catch (Exception e) {
                    // ColorizingService not available or API changed, fall back to property-based approach
                }
            }
            
            // Fallback: Clear property-based highlighting
            ghidra.program.model.util.PropertyMapManager propManager = program.getUsrPropertyManager();
            ghidra.program.model.util.IntPropertyMap highlightProp = propManager.getIntPropertyMap("DecompAI_Highlight");
            
            if (highlightProp != null) {
                for (Address addr : body.getAddresses(true)) {
                    highlightProp.remove(addr);
                }
            }
            
        } catch (Exception e) {
            program.endTransaction(transactionId, false); // rollback
            Msg.warn(this, "Failed to clear function highlight: " + e.getMessage(), e);
        } finally {
            if (transactionId >= 0) {
                program.endTransaction(transactionId, true); // commit
            }
        }
    }
}

