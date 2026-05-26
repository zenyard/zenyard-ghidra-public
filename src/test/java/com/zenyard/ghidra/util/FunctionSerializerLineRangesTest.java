package com.zenyard.ghidra.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.model.AddressDetail;
import com.zenyard.ghidra.api.generated.model.LineRange;
import com.zenyard.ghidra.api.generated.model.RangeDetail;
import com.zenyard.ghidra.util.FunctionSerializer.CodeAndLineRanges;
import com.zenyard.ghidra.util.FunctionSerializer.LineData;
import com.zenyard.ghidra.util.FunctionSerializer.TokenData;

/**
 * Verifies the line-aware token walk: code carries newlines and indent, line_ranges anchor
 * each line to an instruction address, and consecutive same-id lines collapse into a single
 * {@link LineRange} entry.
 */
class FunctionSerializerLineRangesTest {

    private static TokenData plain(String text) {
        return new TokenData(text, null);
    }

    private static TokenData addr(String text, String hex) {
        AddressDetail ad = new AddressDetail();
        ad.setAddress(hex);
        RangeDetail detail = new RangeDetail();
        detail.setActualInstance(ad);
        return new TokenData(text, detail);
    }

    private static LineData line(int indent, String id, TokenData... tokens) {
        return new LineData(indent, id, List.of(tokens));
    }

    @Test
    void emptyLinesProduceEmptyOutput() {
        CodeAndLineRanges r = FunctionSerializer.buildCodeAndLineRanges(List.of());
        assertEquals("", r.code());
        assertTrue(r.ranges().isEmpty());
        assertTrue(r.lineRanges().isEmpty());
    }

    @Test
    void singleLineEmitsNewlineAndOneLineRange() {
        CodeAndLineRanges r = FunctionSerializer.buildCodeAndLineRanges(
                List.of(line(0, "401000", plain("return"), plain(" "), plain("0;"))));
        assertEquals("return 0;\n", r.code());
        assertEquals(1, r.lineRanges().size());
        assertEquals("401000", r.lineRanges().get(0).getId());
        assertEquals(1, r.lineRanges().get(0).getLineCount());
    }

    @Test
    void indentIsAppliedAsLeadingSpaces() {
        // PrettyPrinter.INDENT_STRING is a single space; indent=2 → two leading spaces.
        CodeAndLineRanges r = FunctionSerializer.buildCodeAndLineRanges(
                List.of(line(2, "401000", plain("x++;"))));
        assertEquals("  x++;\n", r.code());
    }

    @Test
    void consecutiveSameIdLinesCollapseToOneEntry() {
        CodeAndLineRanges r = FunctionSerializer.buildCodeAndLineRanges(List.of(
                line(0, "401000", plain("a();")),
                line(0, "401000", plain("b();")),
                line(0, "401000", plain("c();"))
        ));
        assertEquals(1, r.lineRanges().size());
        assertEquals("401000", r.lineRanges().get(0).getId());
        assertEquals(3, r.lineRanges().get(0).getLineCount());
    }

    @Test
    void distinctIdsKeepSeparateEntriesAndPreserveOrder() {
        CodeAndLineRanges r = FunctionSerializer.buildCodeAndLineRanges(List.of(
                line(0, "header", plain("void foo(void)")),
                line(0, "header", plain("{")),
                line(1, "401000", plain("a();")),
                line(1, "401004", plain("b();")),
                line(0, "tail", plain("}"))
        ));
        assertEquals(4, r.lineRanges().size());
        assertEquals("header", r.lineRanges().get(0).getId());
        assertEquals(2, r.lineRanges().get(0).getLineCount());
        assertEquals("401000", r.lineRanges().get(1).getId());
        assertEquals("401004", r.lineRanges().get(2).getId());
        assertEquals("tail", r.lineRanges().get(3).getId());
    }

    @Test
    void rangesAreOffsetByIndentAndPreviousLines() {
        CodeAndLineRanges r = FunctionSerializer.buildCodeAndLineRanges(List.of(
                line(0, "401000", plain("first;")),
                line(2, "401004", addr("g_var", "00000000004010a0"))
        ));
        // "first;\n" = 7 chars, then "  " indent (2), so the addressed token starts at offset 9.
        assertEquals("first;\n  g_var\n", r.code());
        assertEquals(1, r.ranges().size());
        assertEquals(9, r.ranges().get(0).getStart());
        assertEquals(5, r.ranges().get(0).getLength());
    }

    @Test
    void totalLineCountMatchesNewlinesInCode() {
        // Server contract: line_ranges' summed line_count must cover every line.
        CodeAndLineRanges r = FunctionSerializer.buildCodeAndLineRanges(List.of(
                line(0, "header", plain("void foo()")),
                line(0, "header", plain("{")),
                line(1, "401000", plain("a();")),
                line(1, "401000", plain("b();")),
                line(0, "tail", plain("}"))
        ));
        long newlines = r.code().chars().filter(c -> c == '\n').count();
        long covered = r.lineRanges().stream().mapToInt(LineRange::getLineCount).sum();
        assertEquals(newlines, covered);
    }

    @Test
    void serverLineCountFormulaMatchesLineRangesSum() {
        // The server validator computes code_lines = code.rstrip("\n").count("\n") + 1.
        // Our line_ranges sum must equal that, otherwise the upload is rejected with
        // "Code has X lines but ranges cover Y lines".
        CodeAndLineRanges r = FunctionSerializer.buildCodeAndLineRanges(List.of(
                line(0, "header", plain("void foo()")),
                line(0, "header", plain("{")),
                line(1, "401000", plain("a();")),
                line(1, "401004", plain("b();")),
                line(0, "tail", plain("}"))
        ));
        String stripped = r.code().replaceAll("\\n+$", "");
        long internalNewlines = stripped.chars().filter(c -> c == '\n').count();
        int codeLines = (int) internalNewlines + 1;
        long covered = r.lineRanges().stream().mapToInt(LineRange::getLineCount).sum();
        assertEquals(codeLines, covered);
    }
}
