package com.zenyard.ghidra.illum;

import java.util.Map;

import com.zenyard.ghidra.api.generated.model.ParametersMapping;
import com.zenyard.ghidra.util.ZenyardConstants;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Applies parameter name mappings for a function.
 */
public class ParameterRenamer {

    public void applyParametersMapping(Program program, Address address, ParametersMapping mapping) {
        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionAt(address);
        if (function == null) {
            Msg.warn(this, "No function at address " + address);
            return;
        }

        DecompilerManager decompilerManager = new DecompilerManager();
        DecompileResults results = decompilerManager.decompileFunction(
            program, function, ZenyardConstants.DECOMPILER_TIMEOUT_SECONDS, TaskMonitor.DUMMY);
            if (!results.decompileCompleted()) {
                throw new RuntimeException("Failed to decompile function: "
                    + (results.getErrorMessage() != null ? results.getErrorMessage() : "Unknown error"));
            }

            Map<String, String> parametersMapping = mapping.getParametersMapping();
            if (parametersMapping == null || parametersMapping.isEmpty()) {
                return;
            }

            Parameter[] parameters = function.getParameters();
            for (Map.Entry<String, String> entry : parametersMapping.entrySet()) {
                int index;
                try {
                    index = Integer.parseInt(entry.getKey());
                } catch (NumberFormatException e) {
                    continue;
                }
                if (index < 0 || index >= parameters.length) {
                    continue;
                }
                Parameter param = parameters[index];
                if (param == null) {
                    continue;
                }
                String nameToApply = entry.getValue();
                if (nameToApply == null) {
                    continue;
                }
                String currentType = param.getDataType() != null ? param.getDataType().getName() : "unknown";
                Msg.debug(this, "Parameter mapping: index=" + index + " -> " + nameToApply
                    + " (currentType=" + currentType + ")");
                if (InferenceNameUtils.isPlaceholderName(nameToApply)) {
                    continue;
                }
                if (!InferenceNameUtils.isValidName(nameToApply)) {
                    nameToApply = "_" + nameToApply;
                }

                try {
                    param.setName(nameToApply, SourceType.USER_DEFINED);
                } catch (DuplicateNameException | InvalidInputException e) {
                    Msg.debug(this, "Parameter rename conflict for " + index + ": " + e.getMessage());
                } catch (Exception e) {
                    Msg.warn(this, "Failed to rename parameter at index " + index + ": " + e.getMessage(), e);
                }
            }
    }
}
