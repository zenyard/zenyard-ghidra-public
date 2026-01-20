package com.zenyard.decompai.ghidra.copilot.tools;

import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.zenyard.decompai.ghidra.api.generated.model.SwiftFunction;
import com.zenyard.decompai.ghidra.storage.InferenceStorage;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Utility methods for Swift-related operations.
 * Mirrors decompai_ida/swift_utils.py
 */
public class SwiftUtils {
    
    private static final Gson gson = new GsonBuilder().create();
    
    /**
     * Check if the program is a Swift binary.
     * Mirrors is_swift_binary_sync() in decompai_ida/swift_utils.py
     * 
     * In IDA, this checks: ida_nalt.get_abi_name() == "swift"
     * In Ghidra, we check the program's language or compiler spec.
     */
    public static boolean isSwiftBinary(Program program) {
        if (program == null) {
            return false;
        }
        
        try {
            // Check program language - Swift binaries typically have "swift" in the language name
            String languageID = program.getLanguageID().getIdAsString().toLowerCase();
            if (languageID.contains("swift")) {
                return true;
            }
            
            // Check compiler spec - Swift binaries may have "swift" in compiler spec
            String compilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
            if (compilerSpec.contains("swift")) {
                return true;
            }
            
            // TODO: Check for Swift-specific metadata or ABI information
            // This is a simplified check - may need enhancement based on actual Swift binary characteristics
            
        } catch (Exception e) {
            Msg.warn(SwiftUtils.class, "Error checking if binary is Swift: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Find the latest SwiftFunction inference for the given address.
     * Mirrors find_latest_swift_function_inference_sync() in decompai_ida/swift_utils.py
     * 
     * @param program The program
     * @param address The function address
     * @return The SwiftFunction inference, or null if not found
     */
    public static SwiftFunction findLatestSwiftFunctionInference(Program program, Address address) {
        if (program == null || address == null) {
            return null;
        }
        
        try {
            InferenceStorage storage = new InferenceStorage(program);
            String addressStr = address.toString();
            
            // Try to get inference data for this address
            InferenceStorage.InferenceData data = storage.getInference(addressStr);
            if (data == null) {
                return null;
            }
            
            // Check if it's a SwiftFunction type
            if (!"swift_function".equals(data.getType())) {
                return null;
            }
            
            // Deserialize the SwiftFunction from the stored data
            // The data map should contain the SwiftFunction fields
            Map<String, Object> dataMap = data.getData();
            if (dataMap == null || dataMap.isEmpty()) {
                return null;
            }
            
            // Convert the data map to JSON and deserialize as SwiftFunction
            String json = gson.toJson(dataMap);
            SwiftFunction swiftFunction = gson.fromJson(json, SwiftFunction.class);
            
            // Set the address if not already set
            if (swiftFunction.getAddress() == null) {
                // Create API Address from Ghidra Address
                String apiAddress = com.zenyard.decompai.ghidra.api.AddressHelper.fromAddress(address);
                swiftFunction.setAddress(apiAddress);
            }
            
            return swiftFunction;
            
        } catch (Exception e) {
            Msg.warn(SwiftUtils.class, "Error finding SwiftFunction inference for address " + address + ": " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Check if Swift source is available for a function at the given address.
     * 
     * @param program The program
     * @param address The function address
     * @return true if Swift source is available, false otherwise
     */
    public static boolean hasSwiftSource(Program program, Address address) {
        SwiftFunction swiftFunction = findLatestSwiftFunctionInference(program, address);
        return swiftFunction != null && swiftFunction.getSource() != null && !swiftFunction.getSource().isEmpty();
    }
}

