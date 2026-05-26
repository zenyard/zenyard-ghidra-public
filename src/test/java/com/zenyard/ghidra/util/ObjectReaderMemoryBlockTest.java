package com.zenyard.ghidra.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Verifies that only blocks in a loaded address space are enumerated for
 * global variable detection. OTHER_SPACE blocks (ELF section headers,
 * {@code .shstrtab}, {@code .strtab}, etc.) live at synthetic addresses that
 * alias real loaded-segment addresses once serialised as plain hex, causing
 * duplicates in a single upload chunk and tripping the server's
 * {@code objects (binary_id, address, min_revision)} primary key.
 */
class ObjectReaderMemoryBlockTest {

    private static MemoryBlock blockInSpace(boolean loaded) {
        MemoryBlock block = mock(MemoryBlock.class);
        Address start = mock(Address.class);
        AddressSpace space = mock(AddressSpace.class);
        when(block.getStart()).thenReturn(start);
        when(start.getAddressSpace()).thenReturn(space);
        when(space.isLoadedMemorySpace()).thenReturn(loaded);
        return block;
    }

    @Test
    void loadedBlockIsEnumerated() {
        assertTrue(
            ObjectReader.shouldEnumerateMemoryBlockForGlobals(blockInSpace(true))
        );
    }

    @Test
    void otherSpaceBlockIsNotEnumerated() {
        assertFalse(
            ObjectReader.shouldEnumerateMemoryBlockForGlobals(blockInSpace(false))
        );
    }

    @Test
    void nullBlockIsNotEnumerated() {
        assertFalse(ObjectReader.shouldEnumerateMemoryBlockForGlobals(null));
    }
}
