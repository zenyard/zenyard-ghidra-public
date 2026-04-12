package com.zenyard.ghidra.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.model.AddressDetail;
import com.zenyard.ghidra.api.generated.model.LVarDetail;
import com.zenyard.ghidra.api.generated.model.Range;
import com.zenyard.ghidra.api.generated.model.RangeDetail;
import com.zenyard.ghidra.util.FunctionSerializer.CodeAndRanges;
import com.zenyard.ghidra.util.FunctionSerializer.TokenData;

/**
 * Unit tests for the token-walk algorithm in FunctionSerializer.
 *
 * Tests operate on TokenData (text + pre-resolved RangeDetail) and drive
 * buildCodeAndRanges directly, so no Ghidra runtime is required.
 */
class FunctionSerializerTokenWalkTest {

    // ---- helpers ----------------------------------------------------------

    private static TokenData plain(String text) {
        return new TokenData(text, null);
    }

    private static TokenData withAddress(String text, String address) {
        AddressDetail ad = new AddressDetail();
        ad.setAddress(address);
        RangeDetail detail = new RangeDetail();
        detail.setActualInstance(ad);
        return new TokenData(text, detail);
    }

    private static TokenData withLVar(String text, String name, boolean isArg) {
        LVarDetail lv = new LVarDetail();
        lv.setName(name);
        lv.setIsArg(isArg);
        RangeDetail detail = new RangeDetail();
        detail.setActualInstance(lv);
        return new TokenData(text, detail);
    }

    private static AddressDetail addressDetail(Range r) {
        return (AddressDetail) r.getDetail().getActualInstance();
    }

    private static LVarDetail lvarDetail(Range r) {
        return (LVarDetail) r.getDetail().getActualInstance();
    }

    // ---- tests -----------------------------------------------------------

    @Test
    void emptyTokenListReturnsEmptyCodeAndNoRanges() {
        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(List.of());

        assertEquals("", result.code());
        assertTrue(result.ranges().isEmpty());
    }

    @Test
    void singlePlainTokenAppendsTextWithNoRange() {
        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(List.of(plain("void")));

        assertEquals("void", result.code());
        assertTrue(result.ranges().isEmpty());
    }

    @Test
    void nullTextTokenIsSkipped() {
        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(
                List.of(new TokenData(null, null)));

        assertEquals("", result.code());
        assertTrue(result.ranges().isEmpty());
    }

    @Test
    void emptyTextTokenIsSkipped() {
        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(
                List.of(new TokenData("", null)));

        assertEquals("", result.code());
        assertTrue(result.ranges().isEmpty());
    }

    @Test
    void singleAddressDetailTokenCreatesRangeAtOffsetZero() {
        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(
                List.of(withAddress("foo", "000000000040100a")));

        assertEquals("foo", result.code());
        assertEquals(1, result.ranges().size());
        Range r = result.ranges().get(0);
        assertEquals(0, r.getStart());
        assertEquals(3, r.getLength());
        assertEquals("000000000040100a", addressDetail(r).getAddress());
    }

    @Test
    void singleLVarTokenLocalVariableCreatesRangeWithIsArgFalse() {
        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(
                List.of(withLVar("local_x", "local_x", false)));

        assertEquals("local_x", result.code());
        assertEquals(1, result.ranges().size());
        Range r = result.ranges().get(0);
        assertEquals(0, r.getStart());
        assertEquals(7, r.getLength());
        LVarDetail lv = lvarDetail(r);
        assertEquals("local_x", lv.getName());
        assertFalse(lv.getIsArg());
    }

    @Test
    void singleLVarTokenParameterCreatesRangeWithIsArgTrue() {
        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(
                List.of(withLVar("param", "param", true)));

        LVarDetail lv = lvarDetail(result.ranges().get(0));
        assertEquals("param", lv.getName());
        assertTrue(lv.getIsArg());
    }

    @Test
    void rangeStartIsOffsetAfterLeadingPlainText() {
        List<TokenData> tokens = List.of(
                plain("void "),                               // len 5, no range
                withAddress("foo", "0000000000401000"),       // offset 5, len 3
                plain("(")                                    // no range
        );

        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(tokens);

        assertEquals("void foo(", result.code());
        assertEquals(1, result.ranges().size());
        Range r = result.ranges().get(0);
        assertEquals(5, r.getStart());
        assertEquals(3, r.getLength());
    }

    @Test
    void multipleRangesHaveCorrectIndependentOffsets() {
        List<TokenData> tokens = List.of(
                withLVar("param1", "param1", true),    // offset 0, len 6
                plain(", "),                            // offset 6, len 2 (no range)
                withLVar("param2", "param2", true)     // offset 8, len 6
        );

        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(tokens);

        assertEquals("param1, param2", result.code());
        assertEquals(2, result.ranges().size());
        assertEquals(0, result.ranges().get(0).getStart());
        assertEquals(6, result.ranges().get(0).getLength());
        assertEquals(8, result.ranges().get(1).getStart());
        assertEquals(6, result.ranges().get(1).getLength());
    }

    @Test
    void codeStringIsExactConcatenationOfAllTokenTexts() {
        List<TokenData> tokens = List.of(
                plain("int "),
                withLVar("x", "x", false),
                plain(" = "),
                withAddress("foo", "0000000000401000"),
                plain("();")
        );

        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(tokens);

        assertEquals("int x = foo();", result.code());
    }

    @Test
    void lastTokenTaggedRangeStartAccountsForAllPrecedingText() {
        String prefix = "return ";
        List<TokenData> tokens = List.of(
                plain(prefix),
                withAddress("bar", "0000000000402000")
        );

        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(tokens);

        assertEquals(prefix.length(), result.ranges().get(0).getStart());
        assertEquals("bar".length(), result.ranges().get(0).getLength());
    }

    @Test
    void mixedDetailTypesRangesCarryCorrectDetailInstances() {
        List<TokenData> tokens = List.of(
                withAddress("callee", "0000000000401234"),
                plain("("),
                withLVar("arg", "arg", true),
                plain(")")
        );

        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(tokens);

        assertEquals("callee(arg)", result.code());
        assertEquals(2, result.ranges().size());
        assertNotNull(addressDetail(result.ranges().get(0)));
        assertNotNull(lvarDetail(result.ranges().get(1)));
    }

    @Test
    void nullTextTokenAmidTaggedTokensDoesNotShiftOffsets() {
        List<TokenData> tokens = List.of(
                withLVar("a", "a", false),
                new TokenData(null, null),
                withLVar("b", "b", false)
        );

        CodeAndRanges result = FunctionSerializer.buildCodeAndRanges(tokens);

        assertEquals("ab", result.code());
        assertEquals(2, result.ranges().size());
        assertEquals(0, result.ranges().get(0).getStart());
        assertEquals(1, result.ranges().get(1).getStart());
    }
}
