package com.zenyard.ghidra.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * Verifies the auto-named string-literal exclusion that mirrors
 * {@code decompai_ida.objects._all_global_variable_symbols_sync}.
 */
class ObjectReaderStringFilterTest {

    @Test
    void autoNamedStringIsExcluded() {
        Data data = mock(Data.class);
        when(data.hasStringValue()).thenReturn(true);

        Symbol symbol = mock(Symbol.class);
        when(symbol.getSource()).thenReturn(SourceType.DEFAULT);

        assertTrue(ObjectReader.isAutoNamedStringLiteral(data, symbol));
    }

    @Test
    void userNamedStringIsKept() {
        Data data = mock(Data.class);
        when(data.hasStringValue()).thenReturn(true);

        Symbol symbol = mock(Symbol.class);
        when(symbol.getSource()).thenReturn(SourceType.USER_DEFINED);

        assertFalse(ObjectReader.isAutoNamedStringLiteral(data, symbol));
    }

    @Test
    void importedNameOnStringIsKept() {
        Data data = mock(Data.class);
        when(data.hasStringValue()).thenReturn(true);

        Symbol symbol = mock(Symbol.class);
        when(symbol.getSource()).thenReturn(SourceType.IMPORTED);

        assertFalse(ObjectReader.isAutoNamedStringLiteral(data, symbol));
    }

    @Test
    void nonStringDataIsKept() {
        Data data = mock(Data.class);
        when(data.hasStringValue()).thenReturn(false);

        assertFalse(ObjectReader.isAutoNamedStringLiteral(data, null));
    }

    @Test
    void stringWithoutPrimarySymbolIsExcluded() {
        Data data = mock(Data.class);
        when(data.hasStringValue()).thenReturn(true);

        assertTrue(ObjectReader.isAutoNamedStringLiteral(data, null));
    }

    @Test
    void nullDataIsKept() {
        assertFalse(ObjectReader.isAutoNamedStringLiteral(null, mock(Symbol.class)));
    }
}
