package com.zenyard.ghidra.upload;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import ghidra.program.model.address.Address;

/**
 * Sections must lead, globals next, everything else last — and an address that
 * shows up in both the section set and the global set is appended exactly once.
 * The dedup is what stops the upload chunk from producing two objects sharing
 * {@code (binary_id, address, min_revision)} and tripping {@code objects_pkey}.
 */
class QueueRevisionsTaskReorderTest {

    private static Address addr() {
        return mock(Address.class);
    }

    @Test
    void sections_then_globals_then_others_in_original_order() {
        Address fn1 = addr();
        Address sec = addr();
        Address glb = addr();
        Address fn2 = addr();
        List<Address> ordered = List.of(fn1, sec, glb, fn2);
        Set<Address> sections = new HashSet<>(List.of(sec));
        Set<Address> globals = new HashSet<>(List.of(glb));

        List<Address> result =
            QueueRevisionsTask.reorderSectionsAndGlobalsFirst(
                ordered, sections, globals);

        assertEquals(List.of(sec, glb, fn1, fn2), result);
    }

    @Test
    void address_in_both_sections_and_globals_is_emitted_once_in_section_band() {
        Address both = addr();
        Address fn = addr();
        List<Address> ordered = List.of(both, fn);
        Set<Address> sections = new HashSet<>(List.of(both));
        Set<Address> globals = new HashSet<>(List.of(both));

        List<Address> result =
            QueueRevisionsTask.reorderSectionsAndGlobalsFirst(
                ordered, sections, globals);

        // The "both" address must appear once and in the section band (first).
        assertEquals(List.of(both, fn), result);
    }

    @Test
    void duplicate_address_in_input_is_emitted_once() {
        Address a = addr();
        Address b = addr();
        List<Address> ordered = List.of(a, b, a);
        Set<Address> sections = new HashSet<>();
        Set<Address> globals = new HashSet<>();

        List<Address> result =
            QueueRevisionsTask.reorderSectionsAndGlobalsFirst(
                ordered, sections, globals);

        assertEquals(List.of(a, b), result);
    }

    @Test
    void empty_section_and_global_sets_preserves_input_order_with_dedup() {
        Address a = addr();
        Address b = addr();
        Address c = addr();
        List<Address> ordered = List.of(a, b, c, a, b);

        List<Address> result =
            QueueRevisionsTask.reorderSectionsAndGlobalsFirst(
                ordered, new HashSet<>(), new HashSet<>());

        assertEquals(List.of(a, b, c), result);
    }

    @Test
    void section_only_address_lands_in_section_band() {
        Address sec = addr();
        Address fn = addr();
        List<Address> ordered = List.of(fn, sec);
        Set<Address> sections = new HashSet<>(List.of(sec));
        Set<Address> globals = new HashSet<>();

        List<Address> result =
            QueueRevisionsTask.reorderSectionsAndGlobalsFirst(
                ordered, sections, globals);

        assertEquals(List.of(sec, fn), result);
        // Sanity: not the same identity (a fresh list).
        assertSame(sec, result.get(0));
    }
}
