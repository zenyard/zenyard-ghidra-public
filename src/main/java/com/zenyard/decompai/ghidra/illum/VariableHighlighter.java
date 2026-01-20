package com.zenyard.decompai.ghidra.illum;

import java.awt.Color;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.task.TaskMonitor;

/**
 * Handles local/global variable highlighting using Ghidra decompiler API.
 * 
 * Uses DecompInterface, HighFunction to identify local variables.
 * 
 * NOTE: mirrors functionality in decompai_ida for variable highlighting.
 * All program modifications use Ghidra's transaction system.
 */
public class VariableHighlighter {
    
    /**
     * Highlight a variable with the given color.
     * 
     * @param program The program
     * @param function The function containing the variable
     * @param variableName The name of the variable to highlight
     * @param color The color to use for highlighting
     * @param tool Optional PluginTool for ColorizingService (can be null)
     */
    public void highlightVariable(Program program, Function function, String variableName, Color color, ghidra.framework.plugintool.PluginTool tool) {
        int transactionId = program.startTransaction("DecompAI: Highlight variable");
        try {
            // Get decompiler interface
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(program);
            
            try {
                // Decompile function
                DecompileOptions options = new DecompileOptions();
                decompiler.setOptions(options);
                
                DecompileResults results = decompiler.decompileFunction(function, 
                    30, TaskMonitor.DUMMY);
                
                if (results.decompileCompleted()) {
                    HighFunction highFunction = results.getHighFunction();
                    if (highFunction != null) {
                        // Find variable in local symbol map
                        Iterator<HighSymbol> localSymbolsIter = highFunction.getLocalSymbolMap().getSymbols();
                        List<HighSymbol> localSymbols = new ArrayList<>();
                        localSymbolsIter.forEachRemaining(localSymbols::add);
                        for (HighSymbol symbol : localSymbols) {
                            if (variableName.equals(symbol.getName())) {
                                // Get addresses where this variable is used
                                HighVariable var = symbol.getHighVariable();
                                if (var != null) {
                                    highlightVariableAddresses(program, var, color, tool);
                                }
                                break;
                            }
                        }
                        
                        // Also check global symbol map
                        Iterator<HighSymbol> globalSymbolsIter = highFunction.getGlobalSymbolMap().getSymbols();
                        List<HighSymbol> globalSymbols = new ArrayList<>();
                        globalSymbolsIter.forEachRemaining(globalSymbols::add);
                        for (HighSymbol symbol : globalSymbols) {
                            if (variableName.equals(symbol.getName())) {
                                // Get addresses where this variable is used
                                HighVariable var = symbol.getHighVariable();
                                if (var != null) {
                                    highlightVariableAddresses(program, var, color, tool);
                                }
                                break;
                            }
                        }
                    }
                }
            } finally {
                decompiler.closeProgram();
            }
        } catch (Exception e) {
            program.endTransaction(transactionId, false); // rollback
            throw new RuntimeException("Failed to highlight variable: " + e.getMessage(), e);
        } finally {
            if (transactionId >= 0) {
                program.endTransaction(transactionId, true); // commit
            }
        }
    }
    
    /**
     * Highlight multiple variables with different colors.
     * 
     * @param program The program
     * @param function The function containing the variables
     * @param variableColors Map of variable names to colors
     * @param tool Optional PluginTool for ColorizingService (can be null)
     */
    public void highlightVariables(Program program, Function function, Map<String, Color> variableColors, ghidra.framework.plugintool.PluginTool tool) {
        int transactionId = program.startTransaction("DecompAI: Highlight variables");
        try {
            for (Map.Entry<String, Color> entry : variableColors.entrySet()) {
                highlightVariable(program, function, entry.getKey(), entry.getValue(), tool);
            }
        } catch (Exception e) {
            program.endTransaction(transactionId, false); // rollback
            throw e;
        } finally {
            if (transactionId >= 0) {
                program.endTransaction(transactionId, true); // commit
            }
        }
    }
    
    /**
     * Clear highlighting for a function's variables.
     * 
     * @param program The program
     * @param function The function
     * @param tool Optional PluginTool for ColorizingService (can be null)
     */
    public void clearHighlights(Program program, Function function, ghidra.framework.plugintool.PluginTool tool) {
        int transactionId = program.startTransaction("DecompAI: Clear variable highlights");
        try {
            // Clear highlighting for all variables in the function
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(program);
            
            try {
                DecompileOptions options = new DecompileOptions();
                decompiler.setOptions(options);
                
                DecompileResults results = decompiler.decompileFunction(function, 
                    30, TaskMonitor.DUMMY);
                
                if (results.decompileCompleted()) {
                    HighFunction highFunction = results.getHighFunction();
                    if (highFunction != null) {
                        // Clear highlighting for all local symbols
                        Iterator<HighSymbol> localSymbolsIter = highFunction.getLocalSymbolMap().getSymbols();
                        List<HighSymbol> localSymbols = new ArrayList<>();
                        localSymbolsIter.forEachRemaining(localSymbols::add);
                        for (HighSymbol symbol : localSymbols) {
                            HighVariable var = symbol.getHighVariable();
                            if (var != null) {
                                clearVariableHighlighting(program, var, tool);
                            }
                        }
                        
                        // Clear highlighting for all global symbols
                        Iterator<HighSymbol> globalSymbolsIter = highFunction.getGlobalSymbolMap().getSymbols();
                        List<HighSymbol> globalSymbols = new ArrayList<>();
                        globalSymbolsIter.forEachRemaining(globalSymbols::add);
                        for (HighSymbol symbol : globalSymbols) {
                            HighVariable var = symbol.getHighVariable();
                            if (var != null) {
                                clearVariableHighlighting(program, var, tool);
                            }
                        }
                    }
                }
            } finally {
                decompiler.closeProgram();
            }
        } catch (Exception e) {
            program.endTransaction(transactionId, false); // rollback
            throw e;
        } finally {
            if (transactionId >= 0) {
                program.endTransaction(transactionId, true); // commit
            }
        }
    }
    
    /**
     * Highlight addresses where a variable is used.
     */
    private void highlightVariableAddresses(Program program, HighVariable var, Color color, ghidra.framework.plugintool.PluginTool tool) {
        if (tool != null) {
            try {
                // Try to use ColorizingService - API may have changed in Ghidra 12.0
                // TODO: Update with correct Ghidra 12.0 ColorizingService API
                Object colorizingService = tool.getService(Class.forName("ghidra.app.util.viewer.field.ColorizingService"));
                if (colorizingService != null) {
                    // Use reflection to call setBackgroundColor
                    java.lang.reflect.Method setBgMethod = colorizingService.getClass().getMethod("setBackgroundColor", Address.class, java.awt.Color.class);
                    // Get all addresses where this variable is used
                    ghidra.program.model.pcode.Varnode[] instances = var.getInstances();
                    for (ghidra.program.model.pcode.Varnode varnode : instances) {
                        Address addr = varnode.getAddress();
                        if (addr != null) {
                            setBgMethod.invoke(colorizingService, addr, color);
                        }
                    }
                    return; // Successfully used ColorizingService
                }
            } catch (Exception e) {
                // ColorizingService not available or API changed, fall back to property-based approach
            }
        }
        
        // Fallback: Use property-based highlighting
        int rgb = (color.getRed() << 16) | (color.getGreen() << 8) | color.getBlue();
        ghidra.program.model.util.PropertyMapManager propManager = program.getUsrPropertyManager();
        ghidra.program.model.util.IntPropertyMap highlightProp = propManager.getIntPropertyMap("DecompAI_VariableHighlight");
        // In Ghidra 12.0, if map doesn't exist, we skip highlighting (property maps may need to be pre-created)
        if (highlightProp != null) {
            ghidra.program.model.pcode.Varnode[] instances = var.getInstances();
            for (ghidra.program.model.pcode.Varnode varnode : instances) {
                Address addr = varnode.getAddress();
                if (addr != null) {
                    highlightProp.add(addr, rgb);
                }
            }
        }
    }
    
    /**
     * Clear highlighting for a variable.
     */
    private void clearVariableHighlighting(Program program, HighVariable var, ghidra.framework.plugintool.PluginTool tool) {
        if (tool != null) {
            try {
                // Try to use ColorizingService - API may have changed in Ghidra 12.0
                // TODO: Update with correct Ghidra 12.0 ColorizingService API
                Object colorizingService = tool.getService(Class.forName("ghidra.app.util.viewer.field.ColorizingService"));
                if (colorizingService != null) {
                    // Use reflection to call clearBackgroundColor
                    java.lang.reflect.Method clearBgMethod = colorizingService.getClass().getMethod("clearBackgroundColor", Address.class);
                    // Clear using ColorizingService
                    ghidra.program.model.pcode.Varnode[] instances = var.getInstances();
                    for (ghidra.program.model.pcode.Varnode varnode : instances) {
                        Address addr = varnode.getAddress();
                        if (addr != null) {
                            clearBgMethod.invoke(colorizingService, addr);
                        }
                    }
                    return; // Successfully cleared using ColorizingService
                }
            } catch (Exception e) {
                // ColorizingService not available or API changed, fall back to property-based approach
            }
        }
        
        // Fallback: Clear property-based highlighting
        ghidra.program.model.util.PropertyMapManager propManager = program.getUsrPropertyManager();
        ghidra.program.model.util.IntPropertyMap highlightProp = propManager.getIntPropertyMap("DecompAI_VariableHighlight");
        
        if (highlightProp != null) {
            ghidra.program.model.pcode.Varnode[] instances = var.getInstances();
            for (ghidra.program.model.pcode.Varnode varnode : instances) {
                Address addr = varnode.getAddress();
                if (addr != null) {
                    highlightProp.remove(addr);
                }
            }
        }
    }
}

