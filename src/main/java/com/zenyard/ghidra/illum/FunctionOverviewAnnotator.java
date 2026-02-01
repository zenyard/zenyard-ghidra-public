package com.zenyard.ghidra.illum;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.CodeUnit;
import com.zenyard.ghidra.util.TransactionUtils;

/**
 * Adds overview descriptions as plate comments or EOL comments in listing/decompiler views.
 * 
 * NOTE: mirrors functionality in zenyard_ida for adding function overviews.
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
        TransactionUtils.runInTransaction(program, "Zenyard: Add function overview", () -> {
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
        TransactionUtils.runInTransaction(program, "Zenyard: Remove function overview", () -> {
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(entryPoint);
            if (codeUnit != null) {
                program.getListing().setComment(entryPoint, CodeUnit.PLATE_COMMENT, null);
            }
        });
    }
}

