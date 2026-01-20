package com.zenyard.decompai.ghidra.inferences;

import java.util.ArrayList;
import java.util.List;

import com.zenyard.decompai.ghidra.api.generated.model.Inference;
import com.zenyard.decompai.ghidra.illum.InferenceApplier;
import com.zenyard.decompai.ghidra.storage.InferenceStorage;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Manages pending inferences and applies them before reading objects.
 * 
 * Mirrors decompai_ida/inferences.py apply_pending_inferences_sync() logic.
 */
public class PendingInferenceManager {
    
    private final Program program;
    private final InferenceApplier inferenceApplier;
    
    public PendingInferenceManager(Program program, InferenceStorage inferenceStorage, 
                                  InferenceApplier inferenceApplier) {
        this.program = program;
        // Note: inferenceStorage parameter kept for API compatibility but not stored (TODO: implement pending inference storage)
        this.inferenceApplier = inferenceApplier;
    }
    
    /**
     * Apply pending inferences for a specific address.
     * 
     * @param address The address to apply pending inferences for
     */
    public void applyPendingInferences(Address address) {
        if (address == null) {
            return;
        }
        
        // Get pending inferences for this address
        List<Inference> pendingInferences = getPendingInferences(address);
        
        if (pendingInferences.isEmpty()) {
            return;
        }
        
        // Apply inferences (oldest to newest - reverse order)
        // Reverse the list to get oldest to newest
        List<Inference> reversed = new ArrayList<>();
        for (int i = pendingInferences.size() - 1; i >= 0; i--) {
            reversed.add(pendingInferences.get(i));
        }
        
        try {
            inferenceApplier.applyInferences(program, reversed);
            
            // Clear pending inferences after application
            clearPendingInferences(address);
        } catch (Exception e) {
            Msg.warn(this, "Error applying pending inferences at " + address + ": " + e.getMessage(), e);
        }
    }
    
    /**
     * Get pending inferences for an address.
     */
    private List<Inference> getPendingInferences(Address address) {
        // TODO: Implement pending inference storage
        // For now, return empty list
        // This should query InferenceStorage for pending inferences keyed by address
        // The storage format would be: pending_inferences.<address>.<inference_type>
        return new ArrayList<>();
    }
    
    /**
     * Clear pending inferences for an address.
     */
    private void clearPendingInferences(Address address) {
        // TODO: Implement clearing pending inferences
        // This should remove all pending inferences for this address from InferenceStorage
    }
}

