package com.zenyard.ghidra.illum;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import com.zenyard.ghidra.util.TransactionUtils;

/**
 * Uses Ghidra's program APIs to highlight functions by setting background colors on code units.
 * 
 * NOTE: mirrors functionality in zenyard_ida/ui/functions_colorizer_task.py
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
        
        TransactionUtils.runInTransaction(program, "Zenyard: Highlight function", () -> {
            AddressSet body = new AddressSet(function.getBody());
            if (tool != null) {
                ColorizingServiceAdapter.forTool(tool).ifPresent(adapter -> {
                    adapter.setBackground(body, color);
                });
            }
        });
        
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
        
        TransactionUtils.runInTransaction(program, "Zenyard: Clear function highlight", () -> {
            AddressSet body = new AddressSet(function.getBody());
            if (tool != null) {
                ColorizingServiceAdapter.forTool(tool).ifPresent(adapter -> {
                    adapter.clearBackground(body);
                });
            }
        });
    }
}

