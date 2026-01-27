package com.zenyard.decompai.ghidra.illum;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.CodeUnit;
import com.zenyard.decompai.ghidra.util.TransactionUtils;

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
        TransactionUtils.runInTransaction(program, "DecompAI: Add function overview", () -> {
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(entryPoint);
            if (codeUnit != null) {
                program.getListing().setComment(entryPoint, CodeUnit.PLATE_COMMENT, overview);
            }
        });
    }
    
    /**
     * Remove function overview comment.
     * Uses Ghidra's transaction system to ensure atomic updates.
     */
    public void removeOverview(Program program, Function function) {
        Address entryPoint = function.getEntryPoint();
        TransactionUtils.runInTransaction(program, "DecompAI: Remove function overview", () -> {
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(entryPoint);
            if (codeUnit != null) {
                program.getListing().setComment(entryPoint, CodeUnit.PLATE_COMMENT, null);
            }
        });
    }
}

