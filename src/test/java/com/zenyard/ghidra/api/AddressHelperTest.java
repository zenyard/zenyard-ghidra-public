package com.zenyard.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;

class AddressHelperTest {

    @Test
    void fromApiAddressKey_nullProgramOrKey_returnsNull() {
        assertNull(AddressHelper.fromApiAddressKey(null, "0000000000000001"));
        Program program = mock(Program.class);
        assertNull(AddressHelper.fromApiAddressKey(program, null));
        assertNull(AddressHelper.fromApiAddressKey(program, ""));
    }

    @Test
    void fromApiAddressKey_wrongLength_returnsNull() {
        Program program = mock(Program.class);
        assertNull(AddressHelper.fromApiAddressKey(program, "deadbeef"));
    }

    @Test
    void fromApiAddressKey_validHex_returnsDefaultSpaceAddress() {
        Program program = mock(Program.class);
        AddressFactory factory = mock(AddressFactory.class);
        AddressSpace space = mock(AddressSpace.class);
        Address addr = mock(Address.class);
        when(program.getAddressFactory()).thenReturn(factory);
        when(factory.getDefaultAddressSpace()).thenReturn(space);
        when(space.getAddress(0x1000L)).thenReturn(addr);

        assertEquals(addr, AddressHelper.fromApiAddressKey(program, "0000000000001000"));
    }
}
