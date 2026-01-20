package com.zenyard.decompai.ghidra.illum;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.CodeUnit;

/**
 * Adds overview descriptions as plate comments or EOL comments in listing/decompiler views.
 * 
 * NOTE: mirrors functionality in decompai_ida for adding function overviews.
 * 
 * All program modifications use Ghidra's transaction system for atomic updates.
 */
public class FunctionOverviewAnnotator {
    
    /**
     * Add a function overview comment.
     * Uses Ghidra's transaction system to ensure atomic updates.
     */
    public void addOverview(Program program, Function function, String overview) {
        if (overview == null || overview.trim().isEmpty()) {
            return;
        }
        
        Address entryPoint = function.getEntryPoint();
        int transactionId = program.startTransaction("DecompAI: Add function overview");
        try {
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(entryPoint);
            
            if (codeUnit != null) {
                // Add as plate comment (pre-comment)
                program.getListing().setComment(entryPoint, CodeUnit.PLATE_COMMENT, overview);
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
     * Remove function overview comment.
     * Uses Ghidra's transaction system to ensure atomic updates.
     */
    public void removeOverview(Program program, Function function) {
        Address entryPoint = function.getEntryPoint();
        int transactionId = program.startTransaction("DecompAI: Remove function overview");
        try {
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(entryPoint);
            
            if (codeUnit != null) {
                program.getListing().setComment(entryPoint, CodeUnit.PLATE_COMMENT, null);
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
}

