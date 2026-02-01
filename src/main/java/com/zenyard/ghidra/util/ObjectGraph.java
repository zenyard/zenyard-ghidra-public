package com.zenyard.ghidra.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

/**
 * Utility for topological ordering of objects based on dependencies.
 * 
 * Mirrors zenyard_ida/object_graph.py logic.
 * Orders functions and global variables so dependencies come before dependents.
 */
public class ObjectGraph {
    
    /**
     * Symbol representing an object (function or global variable).
     */
    public static class Symbol {
        private final Address address;
        private final String type; // "function" or "global_variable"
        
        public Symbol(Address address, String type) {
            this.address = address;
            this.type = type;
        }
        
        public Address getAddress() {
            return address;
        }
        
        public String getType() {
            return type;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Symbol symbol = (Symbol) o;
            return address.equals(symbol.address) && type.equals(symbol.type);
        }
        
        @Override
        public int hashCode() {
            return address.hashCode() * 31 + type.hashCode();
        }
    }
    
    /**
     * Get objects in approximate topological order.
     * 
     * Dependencies come before dependents. Cycles are handled by removing
     * arbitrary edges until the graph is acyclic.
     * 
     * @param program The program
     * @param symbols List of symbols to order
     * @return Addresses in topological order
     */
    public static List<Address> getObjectsInApproxTopoOrder(Program program, List<Symbol> symbols) {
        // Build dependency graph: obj -> set of dependencies
        Map<Address, Set<Address>> objToDependencies = new HashMap<>();
        
        // Initialize all objects with empty dependencies
        for (Symbol symbol : symbols) {
            objToDependencies.put(symbol.getAddress(), new HashSet<>());
        }
        
        // Add function call dependencies
        for (Symbol symbol : symbols) {
            if ("function".equals(symbol.getType())) {
                addCallDependencies(program, symbol.getAddress(), objToDependencies);
            }
        }
        
        // Add global variable to function dependencies
        for (Symbol symbol : symbols) {
            if ("global_variable".equals(symbol.getType())) {
                addGlobalVariableDependencies(program, symbol.getAddress(), objToDependencies);
            }
        }
        
        // Perform topological sort
        return approxTopoOrder(objToDependencies);
    }
    
    /**
     * Add call dependencies for a function.
     * If function A calls function B, then B is a dependency of A.
     */
    private static void addCallDependencies(Program program, Address functionAddress, 
                                           Map<Address, Set<Address>> objToDependencies) {
        if (!objToDependencies.containsKey(functionAddress)) {
            return;
        }
        
        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionAt(functionAddress);
        if (function == null) {
            return;
        }
        
        // Get all calls from this function
        ReferenceManager refManager = program.getReferenceManager();
        for (Reference ref : refManager.getReferencesFrom(functionAddress)) {
            Address toAddress = ref.getToAddress();
            Function calledFunction = funcManager.getFunctionAt(toAddress);
            
            if (calledFunction != null && calledFunction.getEntryPoint().equals(toAddress)) {
                // This is a call to another function
                Address calleeAddress = calledFunction.getEntryPoint();
                
                // Add as dependency if callee is in our graph
                if (objToDependencies.containsKey(calleeAddress)) {
                    objToDependencies.get(functionAddress).add(calleeAddress);
                }
            }
        }
    }
    
    /**
     * Add dependencies for a global variable.
     * If function A references global variable G, then A is a dependency of G.
     */
    private static void addGlobalVariableDependencies(Program program, Address globalVarAddress,
                                                      Map<Address, Set<Address>> objToDependencies) {
        if (!objToDependencies.containsKey(globalVarAddress)) {
            return;
        }
        
        // Get all references to this global variable
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        
        for (Reference ref : refManager.getReferencesTo(globalVarAddress)) {
            Address fromAddress = ref.getFromAddress();
            Function accessingFunction = funcManager.getFunctionContaining(fromAddress);
            
            if (accessingFunction != null) {
                Address funcAddress = accessingFunction.getEntryPoint();
                
                // Add function as dependency if it's in our graph
                if (objToDependencies.containsKey(funcAddress)) {
                    objToDependencies.get(globalVarAddress).add(funcAddress);
                }
            }
        }
    }
    
    /**
     * Perform approximate topological ordering.
     * Handles cycles by removing edges until graph is acyclic.
     */
    private static List<Address> approxTopoOrder(Map<Address, Set<Address>> graph) {
        // Make a copy of the graph
        Map<Address, Set<Address>> g = new HashMap<>();
        for (Map.Entry<Address, Set<Address>> entry : graph.entrySet()) {
            g.put(entry.getKey(), new HashSet<>(entry.getValue()));
        }
        
        // Try topological sort, removing cycles as needed
        while (true) {
            try {
                return topologicalSort(g);
            } catch (CycleException e) {
                // Remove the edge that caused the cycle
                Address node = e.getNode();
                Address dep = e.getDependency();
                if (g.containsKey(node) && g.get(node).contains(dep)) {
                    g.get(node).remove(dep);
                }
            }
        }
    }
    
    /**
     * Perform topological sort using Kahn's algorithm.
     * Graph maps node -> set of dependencies (nodes this node depends on).
     */
    private static List<Address> topologicalSort(Map<Address, Set<Address>> graph) throws CycleException {
        List<Address> result = new ArrayList<>();
        
        // Calculate in-degrees (how many nodes depend on this node)
        // A node with in-degree 0 has no dependencies or all dependencies are satisfied
        Map<Address, Integer> inDegree = new HashMap<>();
        for (Address node : graph.keySet()) {
            inDegree.put(node, 0);
        }
        
        // For each node, count how many other nodes depend on it
        for (Map.Entry<Address, Set<Address>> entry : graph.entrySet()) {
            Set<Address> dependencies = entry.getValue();
            
            // This node depends on these dependencies
            // So each dependency has this node depending on it
            for (Address dep : dependencies) {
                if (graph.containsKey(dep)) {
                    inDegree.put(dep, inDegree.get(dep) + 1);
                }
            }
        }
        
        // Find all nodes with in-degree 0 (no other nodes depend on them)
        Queue<Address> queue = new LinkedList<>();
        for (Map.Entry<Address, Integer> entry : inDegree.entrySet()) {
            if (entry.getValue() == 0) {
                queue.add(entry.getKey());
            }
        }
        
        // Process nodes
        while (!queue.isEmpty()) {
            Address node = queue.poll();
            result.add(node);
            
            // This node is processed, so reduce in-degree of nodes that depend on it
            Set<Address> dependencies = graph.get(node);
            for (Address dep : dependencies) {
                if (graph.containsKey(dep)) {
                    int newInDegree = inDegree.get(dep) - 1;
                    inDegree.put(dep, newInDegree);
                    if (newInDegree == 0) {
                        queue.add(dep);
                    }
                }
            }
        }
        
        // Check for cycles
        if (result.size() != graph.size()) {
            // There's a cycle - find an edge to remove
            for (Map.Entry<Address, Set<Address>> entry : graph.entrySet()) {
                Address node = entry.getKey();
                if (!result.contains(node)) {
                    // This node is part of a cycle
                    Set<Address> deps = entry.getValue();
                    for (Address dep : deps) {
                        if (!result.contains(dep)) {
                            throw new CycleException(node, dep);
                        }
                    }
                }
            }
            // If we can't find a specific cycle, throw with first remaining node
            for (Map.Entry<Address, Set<Address>> entry : graph.entrySet()) {
                Address node = entry.getKey();
                if (!result.contains(node)) {
                    Set<Address> deps = entry.getValue();
                    if (!deps.isEmpty()) {
                        throw new CycleException(node, deps.iterator().next());
                    }
                }
            }
        }
        
        return result;
    }
    
    /**
     * Exception thrown when a cycle is detected.
     */
    private static class CycleException extends Exception {
        private final Address node;
        private final Address dependency;
        
        public CycleException(Address node, Address dependency) {
            this.node = node;
            this.dependency = dependency;
        }
        
        public Address getNode() {
            return node;
        }
        
        public Address getDependency() {
            return dependency;
        }
    }
}

