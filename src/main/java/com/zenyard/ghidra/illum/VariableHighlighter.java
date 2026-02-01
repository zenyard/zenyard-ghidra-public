package com.zenyard.ghidra.illum;

import java.awt.Color;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.task.TaskMonitor;

import com.zenyard.ghidra.util.ZenyardConstants;
import com.zenyard.ghidra.util.TransactionUtils;

/**
 * Handles local/global variable highlighting using Ghidra decompiler API.
 */
public class VariableHighlighter {

    public void highlightVariable(Program program, Function function, String variableName, Color color,
            ghidra.framework.plugintool.PluginTool tool) {
        if (program == null || function == null || variableName == null) {
            return;
        }
        TransactionUtils.runInTransaction(program, "Zenyard: Highlight variable", () -> {
            forEachMatchingVariable(program, function, variableName, var -> {
                highlightVariableAddresses(var, color, tool);
            });
        });
    }

    public void highlightVariables(Program program, Function function, Map<String, Color> variableColors,
            ghidra.framework.plugintool.PluginTool tool) {
        if (variableColors == null || variableColors.isEmpty()) {
            return;
        }
        TransactionUtils.runInTransaction(program, "Zenyard: Highlight variables", () -> {
            for (Map.Entry<String, Color> entry : variableColors.entrySet()) {
                highlightVariable(program, function, entry.getKey(), entry.getValue(), tool);
            }
        });
    }

    public void clearHighlights(Program program, Function function, ghidra.framework.plugintool.PluginTool tool) {
        if (program == null || function == null) {
            return;
        }
        TransactionUtils.runInTransaction(program, "Zenyard: Clear variable highlights", () -> {
            forEachVariable(program, function, var -> clearVariableHighlighting(var, tool));
        });
    }

    private void forEachMatchingVariable(Program program, Function function, String variableName,
            java.util.function.Consumer<HighVariable> consumer) {
        DecompilerManager decompilerManager = new DecompilerManager();
        DecompileResults results = decompilerManager.decompileFunction(function.getProgram(), function,
            ZenyardConstants.DECOMPILER_TIMEOUT_SECONDS, TaskMonitor.DUMMY);
        if (!results.decompileCompleted()) {
            return;
        }
        HighFunction highFunction = results.getHighFunction();
        if (highFunction == null) {
            return;
        }
        List<HighSymbol> locals = collectSymbols(highFunction.getLocalSymbolMap().getSymbols());
        for (HighSymbol symbol : locals) {
            if (variableName.equals(symbol.getName())) {
                HighVariable var = symbol.getHighVariable();
                if (var != null) {
                    consumer.accept(var);
                }
                return;
            }
        }
        List<HighSymbol> globals = collectSymbols(highFunction.getGlobalSymbolMap().getSymbols());
        for (HighSymbol symbol : globals) {
            if (variableName.equals(symbol.getName())) {
                HighVariable var = symbol.getHighVariable();
                if (var != null) {
                    consumer.accept(var);
                }
                return;
            }
        }
    }

    private void forEachVariable(Program program, Function function,
            java.util.function.Consumer<HighVariable> consumer) {
        DecompilerManager decompilerManager = new DecompilerManager();
        DecompileResults results = decompilerManager.decompileFunction(function.getProgram(), function,
            ZenyardConstants.DECOMPILER_TIMEOUT_SECONDS, TaskMonitor.DUMMY);
        if (!results.decompileCompleted()) {
            return;
        }
        HighFunction highFunction = results.getHighFunction();
        if (highFunction == null) {
            return;
        }
        List<HighSymbol> locals = collectSymbols(highFunction.getLocalSymbolMap().getSymbols());
        for (HighSymbol symbol : locals) {
            HighVariable var = symbol.getHighVariable();
            if (var != null) {
                consumer.accept(var);
            }
        }
        List<HighSymbol> globals = collectSymbols(highFunction.getGlobalSymbolMap().getSymbols());
        for (HighSymbol symbol : globals) {
            HighVariable var = symbol.getHighVariable();
            if (var != null) {
                consumer.accept(var);
            }
        }
    }

    private List<HighSymbol> collectSymbols(Iterator<HighSymbol> iterator) {
        List<HighSymbol> symbols = new ArrayList<>();
        iterator.forEachRemaining(symbols::add);
        return symbols;
    }

    private void highlightVariableAddresses(HighVariable var, Color color, ghidra.framework.plugintool.PluginTool tool) {
        if (tool == null) {
            return;
        }
        List<ghidra.program.model.address.Address> addresses = getVariableAddresses(var);
        ColorizingServiceAdapter.forTool(tool).ifPresent(adapter -> {
            for (ghidra.program.model.address.Address address : addresses) {
                adapter.setBackground(address, color);
            }
        });
    }

    private void clearVariableHighlighting(HighVariable var, ghidra.framework.plugintool.PluginTool tool) {
        if (tool == null) {
            return;
        }
        List<ghidra.program.model.address.Address> addresses = getVariableAddresses(var);
        ColorizingServiceAdapter.forTool(tool).ifPresent(adapter -> {
            for (ghidra.program.model.address.Address address : addresses) {
                adapter.clearBackground(address);
            }
        });
    }

    private List<ghidra.program.model.address.Address> getVariableAddresses(HighVariable var) {
        List<ghidra.program.model.address.Address> addresses = new ArrayList<>();
        if (var == null) {
            return addresses;
        }
        ghidra.program.model.pcode.Varnode[] instances = var.getInstances();
        for (ghidra.program.model.pcode.Varnode varnode : instances) {
            if (varnode.getAddress() != null) {
                addresses.add(varnode.getAddress());
            }
        }
        return addresses;
    }
}

