package com.zenyard.ghidra.illum;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.zenyard.ghidra.api.generated.model.GlobalVariableType;
import com.zenyard.ghidra.api.generated.model.Inference;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;

/**
 * Orders {@code global_variable_type} inferences so that smaller memory footprints
 * apply before larger ones, reducing the chance that a coarse struct clears finer
 * interior typings in the same batch.
 */
public final class GlobalVariableInferenceOrdering {

    private GlobalVariableInferenceOrdering() {
    }

    /**
     * Address-bound global variable type inference for sorting.
     */
    public static final class GlobalVariableInferenceItem {
        public final Address address;
        public final Inference inference;

        public GlobalVariableInferenceItem(Address address, Inference inference) {
            this.address = address;
            this.inference = inference;
        }
    }

    /**
     * Extract a {@link GlobalVariableType} from a typed or map-shaped inference payload.
     */
    public static GlobalVariableType extractGlobalVariableType(Inference inference) {
        if (inference == null) {
            return null;
        }
        Object actual = inference.getActualInstance();
        if (actual instanceof GlobalVariableType) {
            return (GlobalVariableType) actual;
        }
        if (actual instanceof Map<?, ?>) {
            Map<?, ?> map = (Map<?, ?>) actual;
            if (!"global_variable_type".equals(String.valueOf(map.get("type")))) {
                return null;
            }
            GlobalVariableType gvt = new GlobalVariableType();
            Object ta = map.get("type_annotation");
            if (ta != null) {
                gvt.setTypeAnnotation(String.valueOf(ta));
            }
            Object sid = map.get("struct_id");
            if (sid instanceof String && !((String) sid).isBlank()) {
                try {
                    gvt.setStructId(UUID.fromString((String) sid));
                } catch (IllegalArgumentException ignored) {
                    // leave struct_id unset
                }
            }
            return gvt.getTypeAnnotation() != null && !gvt.getTypeAnnotation().isBlank()
                ? gvt
                : null;
        }
        return null;
    }

    /**
     * Resolve byte span for ordering. Unknown or unresolvable types sort last.
     */
    public static int resolveSpanForOrdering(
        Program program,
        StructInferenceApplier structInferenceApplier,
        Inference inference
    ) {
        GlobalVariableType gvt = extractGlobalVariableType(inference);
        if (gvt == null) {
            return Integer.MAX_VALUE;
        }
        DataType resolved = structInferenceApplier.resolveInferenceDataType(
            program,
            gvt.getTypeAnnotation(),
            gvt.getStructId()
        );
        if (resolved == null) {
            return Integer.MAX_VALUE;
        }
        int len = resolved.getLength();
        return len > 0 ? len : Integer.MAX_VALUE;
    }

    /**
     * Sort items by ascending resolved span, then by address (deterministic tie-break).
     */
    public static List<GlobalVariableInferenceItem> sortBySpanAscending(
        Program program,
        StructInferenceApplier structInferenceApplier,
        List<GlobalVariableInferenceItem> items
    ) {
        List<GlobalVariableInferenceItem> copy = new ArrayList<>(items);
        copy.sort(Comparator
            .comparingInt(
                (GlobalVariableInferenceItem it) -> resolveSpanForOrdering(
                    program,
                    structInferenceApplier,
                    it.inference))
            .thenComparing(it -> it.address));
        return copy;
    }
}
