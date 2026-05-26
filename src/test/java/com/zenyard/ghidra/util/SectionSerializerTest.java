package com.zenyard.ghidra.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.model.Section;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Verifies that {@link SectionSerializer#serializeSection} carries permission/class info
 * from the containing memory block onto the API model. Enumeration logic that walks the
 * Program Tree is exercised by the integration test in {@link ObjectReaderMemoryBlockTest}
 * and by smoke-running against a real binary.
 */
class SectionSerializerTest {

    @Test
    void executableBlockIsClassifiedAsCode() {
        MemoryBlock block = mock(MemoryBlock.class);
        when(block.isRead()).thenReturn(true);
        when(block.isWrite()).thenReturn(false);
        when(block.isExecute()).thenReturn(true);

        Address start = mock(Address.class);
        when(start.toString()).thenReturn("00400000");

        SectionSerializer.SectionView view =
            new SectionSerializer.SectionView(start, ".text", 0x100L, block);

        Section section = SectionSerializer.serializeSection(view);
        assertEquals(".text", section.getName());
        assertEquals(Section.ClassEnum.CODE, section.getClassValue());
        assertTrue(section.getRead());
        assertFalse(section.getWrite());
        assertTrue(section.getExecute());
    }

    @Test
    void nonExecutableBlockIsClassifiedAsData() {
        MemoryBlock block = mock(MemoryBlock.class);
        when(block.isRead()).thenReturn(true);
        when(block.isWrite()).thenReturn(true);
        when(block.isExecute()).thenReturn(false);

        Address start = mock(Address.class);
        SectionSerializer.SectionView view =
            new SectionSerializer.SectionView(start, ".data", 0x40L, block);

        Section section = SectionSerializer.serializeSection(view);
        assertEquals(Section.ClassEnum.DATA, section.getClassValue());
        assertTrue(section.getWrite());
    }

    @Test
    void missingContainingBlockYieldsDataWithNoPermissions() {
        // Defensive: a fragment whose start address falls outside any memory block — should
        // not crash, should emit zeroed permissions and a DATA classification.
        Address start = mock(Address.class);
        SectionSerializer.SectionView view =
            new SectionSerializer.SectionView(start, "synthetic", 16L, null);

        Section section = SectionSerializer.serializeSection(view);
        assertEquals(Section.ClassEnum.DATA, section.getClassValue());
        assertFalse(section.getRead());
        assertFalse(section.getWrite());
        assertFalse(section.getExecute());
    }

    @Test
    void fragmentInLoadedMemorySpaceIsUploaded() {
        AddressSpace space = mock(AddressSpace.class);
        when(space.isLoadedMemorySpace()).thenReturn(true);
        Address start = mock(Address.class);
        when(start.getAddressSpace()).thenReturn(space);

        ProgramFragment fragment = mock(ProgramFragment.class);
        when(fragment.isEmpty()).thenReturn(false);
        when(fragment.getMinAddress()).thenReturn(start);

        assertTrue(SectionSerializer.shouldUploadFragment(fragment));
    }

    @Test
    void fragmentInNonLoadedSpaceIsSkipped() {
        // ELF section/program-header fragments live in OTHER_SPACE — useless for
        // global-pattern validation and they collide on address 0x0 if uploaded.
        AddressSpace space = mock(AddressSpace.class);
        when(space.isLoadedMemorySpace()).thenReturn(false);
        Address start = mock(Address.class);
        when(start.getAddressSpace()).thenReturn(space);

        ProgramFragment fragment = mock(ProgramFragment.class);
        when(fragment.isEmpty()).thenReturn(false);
        when(fragment.getMinAddress()).thenReturn(start);

        assertFalse(SectionSerializer.shouldUploadFragment(fragment));
    }

    @Test
    void emptyFragmentIsSkipped() {
        ProgramFragment fragment = mock(ProgramFragment.class);
        when(fragment.isEmpty()).thenReturn(true);
        assertFalse(SectionSerializer.shouldUploadFragment(fragment));
    }
}
