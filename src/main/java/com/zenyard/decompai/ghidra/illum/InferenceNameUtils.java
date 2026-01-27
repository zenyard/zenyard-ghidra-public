package com.zenyard.decompai.ghidra.illum;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.Varnode;

/**
 * Utilities for name validation and variable lookup.
 */
public final class InferenceNameUtils {
    private InferenceNameUtils() {}

    public static boolean isValidName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        if (!name.matches("^[a-zA-Z_][a-zA-Z0-9_]*$")) {
            return false;
        }
        return !name.startsWith("byte_")
            && !name.startsWith("word_")
            && !name.startsWith("dword_")
            && !name.startsWith("qword_");
    }

    public static boolean isPlaceholderName(String name) {
        if (name == null) {
            return true;
        }
        String normalized = name.toLowerCase();
        while (normalized.startsWith("_")) {
            normalized = normalized.substring(1);
        }
        return normalized.startsWith("undefined")
            || normalized.startsWith("unk_")
            || "unknown".equals(normalized);
    }

    public static LocalVariable findLocalVariableByStorage(Function function, Varnode storage) {
        if (function == null || storage == null) {
            return null;
        }
        for (Variable var : function.getLocalVariables()) {
            if (var instanceof LocalVariable) {
                LocalVariable local = (LocalVariable) var;
                ghidra.program.model.listing.VariableStorage variableStorage = local.getVariableStorage();
                if (variableStorage == null) {
                    continue;
                }
                ghidra.program.model.pcode.Varnode[] varnodes = variableStorage.getVarnodes();
                if (varnodes != null) {
                    for (ghidra.program.model.pcode.Varnode varnode : varnodes) {
                        if (storage.equals(varnode)) {
                            return local;
                        }
                        if (varnode != null && storage.getAddress().equals(varnode.getAddress())) {
                            return local;
                        }
                    }
                }
            }
        }
        return null;
    }
}
