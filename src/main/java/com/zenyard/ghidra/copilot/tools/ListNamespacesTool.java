package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

/**
 * Tool to list namespaces (classes/modules) in the program.
 */
public class ListNamespacesTool {
    
    private final CopilotToolContext context;
    
    public ListNamespacesTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a list of namespaces (classes/modules) in the program.")
    public ToolOutput listNamespaces() {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        return ToolUtils.executeTool(context, "list_namespaces", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                SymbolTable symbolTable = program.getSymbolTable();
                SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
                
                Set<String> namespaceSet = new HashSet<>();
                
                while (allSymbols.hasNext()) {
                    context.checkCancelled();
                    
                    Symbol symbol = allSymbols.next();
                    Namespace ns = symbol.getParentNamespace();
                    
                    if (ns != null && !(ns instanceof GlobalNamespace)) {
                        namespaceSet.add(ns.getName());
                    }
                }
                
                // Convert to sorted list
                List<String> allNamespaces = new ArrayList<>(new TreeSet<>(namespaceSet));
                
                StringBuilder output = new StringBuilder();
                for (String nsName : allNamespaces) {
                    output.append(nsName).append("\n");
                }
                return ToolUtils.persistLargeOutput(context, "namespaces", output.toString(), allNamespaces.size());
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list namespaces: " + e.getMessage(), e);
            }
        });
    }
}
