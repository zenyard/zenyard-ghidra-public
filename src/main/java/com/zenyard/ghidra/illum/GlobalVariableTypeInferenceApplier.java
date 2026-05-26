package com.zenyard.ghidra.illum;

import com.zenyard.ghidra.api.generated.model.GlobalVariableType;
import com.zenyard.ghidra.storage.InferenceStorage;

import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;

/**
 * Applies global variable type inferences to program data.
 * <p>
 * Struct array annotations such as {@code struct SampleStruct[4]} are resolved to Ghidra's
 * {@link ArrayDataType} (element type + count + stride). To match the Code Browser workflow
 * (define the element type, then <em>Create Array</em> to expand), we apply arrays with
 * {@link CreateArrayCmd} rather than {@link Listing#createData(Address, DataType)} alone.
 * That is the same command the UI uses; it clears conflicting data and builds one array
 * {@link Data} over the full span. Per-element {@code Data} nodes are not required for
 * correct layout or decompilation.
 * </p>
 */
public class GlobalVariableTypeInferenceApplier {

    public enum ApplyResult {
        APPLIED,
        DEFERRED,
        SKIPPED
    }

    private final InferenceStorage inferenceStorage;
    private final StructInferenceApplier structInferenceApplier;

    public GlobalVariableTypeInferenceApplier(
        InferenceStorage inferenceStorage,
        StructInferenceApplier structInferenceApplier
    ) {
        this.inferenceStorage = inferenceStorage;
        this.structInferenceApplier = structInferenceApplier;
    }

    public ApplyResult applyGlobalVariableType(
        Program program,
        Address address,
        GlobalVariableType inference,
        int deferredAttempts
    ) {
        if (program == null || address == null || inference == null) {
            return ApplyResult.SKIPPED;
        }

        if (program.getMemory().getBlock(address) == null) {
            Msg.warn(this, "Skipping global_variable_type at " + address
                + ": address not in program memory (annotation=" + inference.getTypeAnnotation() + ")");
            return ApplyResult.SKIPPED;
        }

        DataType resolved = structInferenceApplier.resolveInferenceDataType(
            program,
            inference.getTypeAnnotation(),
            inference.getStructId()
        );
        if (resolved == null) {
            Msg.warn(this, "Could not resolve global variable type '" + inference.getTypeAnnotation()
                + "' at " + address + "; deferring");
            inferenceStorage.enqueueDeferredGlobalVariableType(inference, deferredAttempts + 1);
            return ApplyResult.DEFERRED;
        }

        int resolvedLength = resolved.getLength();
        if (resolvedLength <= 0) {
            Msg.warn(this, "Resolved global variable type has zero or unknown length; "
                + "cannot apply struct/array at " + address + " (annotation="
                + inference.getTypeAnnotation() + "); deferring");
            inferenceStorage.enqueueDeferredGlobalVariableType(inference, deferredAttempts + 1);
            return ApplyResult.DEFERRED;
        }

        if (hasInteriorInferredGlobal(program, address, resolvedLength)) {
            Msg.debug(this, "Skipping global_variable_type at " + address
                + " -> " + resolved.getDisplayName()
                + ": interior address already has a finer global_variable_type inference");
            return ApplyResult.SKIPPED;
        }

        Listing listing = program.getListing();
        Data existing = listing.getDataContaining(address);
        if (isEquivalentDataType(existing, resolved)) {
            inferenceStorage.markInferredGlobalVariableType(address, resolved.getPathName());
            Msg.debug(this, "global_variable_type already matches listing at " + address
                + " -> " + resolved.getDisplayName());
            return ApplyResult.APPLIED;
        }

        AddressRange clearRange;
        try {
            clearRange = computeReplacementRange(
                listing,
                address,
                computeEndAddress(address, resolvedLength, program)
            );
        } catch (Exception e) {
            Msg.warn(this, "Failed computing replacement range for global_variable_type at " + address
                + ": " + e.getMessage(), e);
            return ApplyResult.SKIPPED;
        }

        // From this point on, recreateData will clear code units before creating new data.
        // If creation fails after clearing, the caller's transaction must be rolled back to
        // restore any surrounding data that was wiped by the clear. We therefore re-throw
        // so the transaction layer (runInTransaction) sees the failure and calls
        // endTransaction(..., false) instead of committing a partially-cleared listing.
        try {
            recreateData(program, listing, address, resolved, clearRange, false);
        } catch (Exception e) {
            Msg.warn(this, "Failed applying global_variable_type at " + address
                + ": " + e.getMessage(), e);
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new RuntimeException("Failed applying global_variable_type at " + address, e);
        }

        Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
        String typePath = resolved.getPathName();
        inferenceStorage.markInferredGlobalVariableType(address, typePath);

        Data applied = listing.getDataAt(address);
        if (!isEquivalentDataType(applied, resolved)) {
            Msg.warn(this, "Post-apply global variable type mismatch at " + address
                + " expected=" + typePath
                + " actual=" + (applied != null && applied.getDataType() != null
                    ? applied.getDataType().getPathName() : "null"));
        }

        Msg.debug(this, "Applied global_variable_type at " + address
            + " -> " + resolved.getDisplayName()
            + (symbol != null ? " (" + symbol.getName() + ")" : ""));
        return ApplyResult.APPLIED;
    }

    private boolean isEquivalentDataType(Data data, DataType resolved) {
        if (data == null || resolved == null || data.getDataType() == null) {
            return false;
        }
        DataType current = data.getDataType();
        if (current.isEquivalent(resolved)) {
            return true;
        }
        String currentPath = current.getPathName();
        String resolvedPath = resolved.getPathName();
        if (currentPath != null && currentPath.equals(resolvedPath)) {
            return true;
        }
        return current.getDisplayName().equals(resolved.getDisplayName());
    }

    /**
     * If a previous global_variable_type was applied at a strictly interior address
     * (pointer-aligned offset from {@code baseAddr}), skip this coarse apply so finer
     * typings win over merged structs that span the same memory.
     */
    private boolean hasInteriorInferredGlobal(Program program, Address baseAddr, int lengthBytes) {
        if (inferenceStorage == null || lengthBytes <= 1) {
            return false;
        }
        long align = Math.max(1L, (long) program.getDefaultPointerSize());
        final int maxSteps = 65536;
        int steps = 0;
        for (long off = align; off < lengthBytes; off += align) {
            if (++steps > maxSteps) {
                break;
            }
            Address candidate = baseAddr.add(off);
            Address endExclusive = baseAddr.add((long) lengthBytes);
            if (candidate.compareTo(endExclusive) >= 0) {
                break;
            }
            if (inferenceStorage.wasGlobalVariableTypeInferred(candidate)) {
                return true;
            }
        }
        return false;
    }

    private AddressRange computeReplacementRange(
        Listing listing,
        Address requestedStart,
        Address requestedEnd
    ) {
        Address clearStart = requestedStart;
        Address clearEnd = requestedEnd;
        boolean expanded;

        do {
            expanded = false;
            Address cursor = clearStart;
            while (cursor != null && cursor.compareTo(clearEnd) <= 0) {
                Data conflict = listing.getDataContaining(cursor);
                if (conflict != null) {
                    if (conflict.getMinAddress().compareTo(clearStart) < 0) {
                        clearStart = conflict.getMinAddress();
                        expanded = true;
                    }
                    if (conflict.getMaxAddress().compareTo(clearEnd) > 0) {
                        clearEnd = conflict.getMaxAddress();
                        expanded = true;
                    }
                    cursor = conflict.getMaxAddress().next();
                    continue;
                }
                cursor = cursor.next();
            }
        } while (expanded);

        return new AddressRange(clearStart, clearEnd);
    }

    private void recreateData(
        Program program,
        Listing listing,
        Address address,
        DataType resolved,
        AddressRange clearRange,
        boolean clearContext
    ) throws Exception {
        try {
            listing.clearCodeUnits(clearRange.getStart(), clearRange.getEnd(), clearContext);
            createDataOrArray(program, listing, address, resolved);
        } catch (Exception firstFailure) {
            if (clearContext) {
                throw firstFailure;
            }
            Msg.info(this, "Retrying global_variable_type at " + address
                + " with broader clear after: " + firstFailure.getMessage());
            listing.clearCodeUnits(clearRange.getStart(), clearRange.getEnd(), true);
            createDataOrArray(program, listing, address, resolved);
        }
    }

    /**
     * Uses {@link CreateArrayCmd} for {@link ArrayDataType} (same path as the listing
     * <em>Create Array</em> action). Falls back to {@link Listing#createData} if the command
     * fails or the array metadata is unusable.
     */
    private void createDataOrArray(Program program, Listing listing, Address address, DataType resolved)
            throws Exception {
        if (!(resolved instanceof ArrayDataType)) {
            listing.createData(address, resolved);
            return;
        }
        ArrayDataType arrayType = (ArrayDataType) resolved;
        DataType element = arrayType.getDataType();
        int numElements = arrayType.getNumElements();
        if (element == null || numElements <= 0) {
            listing.createData(address, resolved);
            return;
        }
        int elementLength = arrayType.getElementLength();
        if (elementLength <= 0) {
            int fromElem = element.getLength();
            elementLength = fromElem > 0 ? fromElem : Math.max(1, program.getDefaultPointerSize());
        }
        CreateArrayCmd cmd = new CreateArrayCmd(address, numElements, element, elementLength);
        if (!cmd.applyTo(program)) {
            Msg.info(this, "CreateArrayCmd did not apply (" + cmd.getStatusMsg()
                + "); falling back to createData for " + resolved.getDisplayName());
            listing.createData(address, resolved);
        }
    }

    /**
     * Inclusive end address for {@link Listing#clearCodeUnits}. {@code length} must be positive
     * (callers defer when the resolved type has zero length).
     */
    private Address computeEndAddress(Address address, int length, Program program) throws Exception {
        int span = length;
        if (span <= 0 && program != null) {
            span = Math.max(1, program.getDefaultPointerSize());
        }
        return span <= 1 ? address : address.add(span - 1L);
    }

    private static class AddressRange {
        private final Address start;
        private final Address end;

        AddressRange(Address start, Address end) {
            this.start = start;
            this.end = end;
        }

        Address getStart() {
            return start;
        }

        Address getEnd() {
            return end;
        }
    }
}
