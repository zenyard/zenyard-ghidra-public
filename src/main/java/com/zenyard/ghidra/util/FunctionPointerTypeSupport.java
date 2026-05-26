package com.zenyard.ghidra.util;

import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves C abstract function-pointer spellings ({@code void (*)(uint32_t)}) for inference
 * and rewrites prototypes so {@link FunctionSignatureParser} sees simple typedef names.
 */
public final class FunctionPointerTypeSupport {

    /**
     * All plugin-generated function signatures and related typedefs (e.g. fn-ptr helpers)
     * are stored under this category in the program DTM.
     */
    public static final CategoryPath ZENYARD_PROTOTYPES_CATEGORY = new CategoryPath("/zenyard/prototypes");
    private static final String SYNTHETIC_FN_NAME = "zenyard_fnptr_parse_tmp";

    /**
     * Ghidra's {@link FunctionSignatureParser} resolves parameter types by name in the DTM; many
     * binaries lack {@code uint32_t} while built-ins include {@code uint}. Order: longer / more
     * specific tokens first so we do not split compound identifiers.
     */
    private static final String[][] STDINT_TO_GHIDRA_PARSER_NAME = {
        {"uint64_t", "ulonglong"},
        {"uint32_t", "uint"},
        {"uint16_t", "ushort"},
        {"uint8_t", "uchar"},
        {"int64_t", "longlong"},
        {"int32_t", "int"},
        {"int16_t", "short"},
        {"int8_t", "char"},
        {"uintptr_t", "ulonglong"},
        {"intptr_t", "longlong"},
        {"size_t", "ulonglong"},
        {"ssize_t", "longlong"},
    };

    private FunctionPointerTypeSupport() {
    }

    /**
     * True if the annotation likely uses C abstract function-pointer syntax ({@code (*)(...)}).
     * Used to fall back to annotation-based resolution when {@code struct_id} is set but the
     * struct type is not yet in the DTM.
     */
    public static boolean annotationLooksLikeAbstractFunctionPointer(String typeAnnotation) {
        if (typeAnnotation == null) {
            return false;
        }
        return typeAnnotation.contains("(*");
    }

    /**
     * Removes trailing whitespace and {@code *} tokens (pointer depth suffix).
     */
    public static String stripTrailingPointerSuffix(String s) {
        if (s == null) {
            return null;
        }
        int i = s.length() - 1;
        while (i >= 0) {
            char c = s.charAt(i);
            if (c == '*') {
                i--;
                continue;
            }
            if (Character.isWhitespace(c)) {
                i--;
                continue;
            }
            break;
        }
        return s.substring(0, i + 1).trim();
    }

    /**
     * If {@code typeAnnotation} is exactly an abstract function-pointer type, returns
     * {@link PointerDataType} to the parsed {@link FunctionDefinitionDataType}; otherwise null.
     */
    public static DataType tryResolveAbstractFunctionPointer(Program program, String typeAnnotation) {
        if (program == null || typeAnnotation == null) {
            return null;
        }
        String s = typeAnnotation.trim();
        if (s.isEmpty()) {
            return null;
        }
        AbstractFnPtrMatch m = tryMatchAbstractFunctionPointerAt(s, 0);
        if (m == null || m.start != 0 || m.end != s.length()) {
            return null;
        }
        return buildPointerToFunction(program, m.returnType, m.paramListInner);
    }

    /**
     * Replaces abstract function-pointer substrings with typedefs under {@code /zenyard/prototypes},
     * shortest-inner matches first so nested forms normalize correctly.
     */
    public static String preprocessPrototypeForSignatureParser(Program program, String prototype) {
        if (program == null || prototype == null || prototype.isBlank()) {
            return prototype;
        }
        DataTypeManager dtm = program.getDataTypeManager();
        AtomicInteger seq = new AtomicInteger(0);
        String s = prototype;
        while (true) {
            AbstractFnPtrMatch m = findShortestAbstractFunctionPointerMatch(s);
            if (m == null) {
                break;
            }
            DataType ptrType = buildPointerToFunction(program, m.returnType, m.paramListInner);
            if (ptrType == null) {
                Msg.warn(FunctionPointerTypeSupport.class,
                    "Skipping abstract function-pointer span; could not build type: "
                        + s.substring(m.start, m.end));
                break;
            }
            String typedefName = allocateTypedefName(dtm, seq);
            try {
                TypedefDataType td = new TypedefDataType(ZENYARD_PROTOTYPES_CATEGORY, typedefName, ptrType, dtm);
                dtm.addDataType(td, DataTypeConflictHandler.REPLACE_HANDLER);
            } catch (Exception e) {
                Msg.warn(FunctionPointerTypeSupport.class,
                    "Failed registering fn-ptr typedef '" + typedefName + "': " + e.getMessage());
                break;
            }
            s = s.substring(0, m.start) + typedefName + s.substring(m.end);
        }
        return s;
    }

    /**
     * Package-private for unit tests: locate shortest abstract function-pointer substring.
     */
    static AbstractFnPtrMatch findShortestAbstractFunctionPointerMatch(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        AbstractFnPtrMatch best = null;
        for (int start = 0; start < s.length(); start++) {
            AbstractFnPtrMatch m = tryMatchAbstractFunctionPointerAt(s, start);
            if (m != null) {
                int len = m.end - m.start;
                if (best == null || len < best.end - best.start) {
                    best = m;
                }
            }
        }
        return best;
    }

    /**
     * Parsed abstract function-pointer span for tests and internal use.
     */
    public static final class AbstractFnPtrMatch {
        public final int start;
        public final int end;
        public final String returnType;
        public final String paramListInner;

        AbstractFnPtrMatch(int start, int end, String returnType, String paramListInner) {
            this.start = start;
            this.end = end;
            this.returnType = returnType;
            this.paramListInner = paramListInner;
        }
    }

    static AbstractFnPtrMatch tryMatchAbstractFunctionPointerAt(String s, int start) {
        if (s == null || start < 0 || start >= s.length()) {
            return null;
        }
        if (!isLikelyTypeSpanStart(s, start)) {
            return null;
        }
        int i = start;
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        int starParenOpen = findAbstractStarParenOpen(s, i);
        if (starParenOpen < 0) {
            return null;
        }
        String returnType = s.substring(i, starParenOpen).trim();
        if (returnType.isEmpty()) {
            return null;
        }
        int afterStarParen = skipAbstractStarParenGroup(s, starParenOpen);
        if (afterStarParen < 0) {
            return null;
        }
        int k = afterStarParen;
        while (k < s.length() && Character.isWhitespace(s.charAt(k))) {
            k++;
        }
        if (k >= s.length() || s.charAt(k) != '(') {
            return null;
        }
        int paramClose = matchingCloseParen(s, k);
        if (paramClose < 0) {
            return null;
        }
        String paramInner = s.substring(k + 1, paramClose).trim();
        return new AbstractFnPtrMatch(start, paramClose + 1, returnType, paramInner);
    }

    private static int findAbstractStarParenOpen(String s, int from) {
        for (int idx = from; idx < s.length(); idx++) {
            if (s.charAt(idx) != '(') {
                continue;
            }
            int j = idx + 1;
            while (j < s.length() && Character.isWhitespace(s.charAt(j))) {
                j++;
            }
            if (j >= s.length() || s.charAt(j) != '*') {
                continue;
            }
            j++;
            while (j < s.length() && Character.isWhitespace(s.charAt(j))) {
                j++;
            }
            if (j < s.length() && s.charAt(j) == ')') {
                return idx;
            }
        }
        return -1;
    }

    private static int skipAbstractStarParenGroup(String s, int openParen) {
        int j = openParen + 1;
        while (j < s.length() && Character.isWhitespace(s.charAt(j))) {
            j++;
        }
        if (j >= s.length() || s.charAt(j) != '*') {
            return -1;
        }
        j++;
        while (j < s.length() && Character.isWhitespace(s.charAt(j))) {
            j++;
        }
        if (j >= s.length() || s.charAt(j) != ')') {
            return -1;
        }
        return j + 1;
    }

    /**
     * Avoid matches that start mid-identifier (e.g. {@code d (*)(void)} inside {@code void}),
     * or the second word of a multi-word return type ({@code int} in {@code unsigned int (*)(...)}).
     */
    private static boolean isLikelyTypeSpanStart(String s, int start) {
        if (start == 0) {
            return true;
        }
        int p = start - 1;
        while (p >= 0 && Character.isWhitespace(s.charAt(p))) {
            p--;
        }
        if (p < 0) {
            return true;
        }
        char c = s.charAt(p);
        if (c == '(' || c == ',' || c == ';' || c == '{') {
            return true;
        }
        return !Character.isJavaIdentifierPart(c);
    }

    private static int matchingCloseParen(String s, int openIdx) {
        int depth = 0;
        for (int idx = openIdx; idx < s.length(); idx++) {
            char c = s.charAt(idx);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth == 0) {
                    return idx;
                }
            }
        }
        return -1;
    }

    /**
     * Rewrites stdint-style names to spellings Ghidra's signature parser usually resolves
     * without program-local typedefs. Package-private for tests.
     */
    static String normalizeStdIntAliasesForSignatureParser(String fragment) {
        if (fragment == null || fragment.isEmpty()) {
            return fragment;
        }
        String s = fragment;
        for (String[] pair : STDINT_TO_GHIDRA_PARSER_NAME) {
            String from = pair[0];
            String to = pair[1];
            Pattern p = Pattern.compile("\\b" + Pattern.quote(from) + "\\b");
            Matcher m = p.matcher(s);
            s = m.replaceAll(Matcher.quoteReplacement(to));
        }
        return s;
    }

    private static DataType buildPointerToFunction(
            Program program,
            String returnType,
            String paramListInner) {
        if (program == null) {
            return null;
        }
        DataTypeManager dtm = program.getDataTypeManager();
        String rt = normalizeStdIntAliasesForSignatureParser(returnType.trim());
        String params = normalizeStdIntAliasesForSignatureParser(paramListInner.trim());
        String synthetic = rt + " " + SYNTHETIC_FN_NAME + "(" + params + ")";
        try {
            FunctionSignatureParser parser =
                new FunctionSignatureParser(dtm, new HeadlessDataTypeQueryService(dtm));
            FunctionDefinitionDataType def = parser.parse(null, synthetic);
            try {
                def.setCategoryPath(ZENYARD_PROTOTYPES_CATEGORY);
            } catch (Exception e) {
                Msg.warn(FunctionPointerTypeSupport.class,
                    "Could not move parsed fn-ptr signature to /zenyard/prototypes: " + e.getMessage());
            }
            DataType resolvedFn = dtm.resolve(def, DataTypeConflictHandler.REPLACE_HANDLER);
            return new PointerDataType(resolvedFn, dtm);
        } catch (Exception e) {
            Msg.debug(FunctionPointerTypeSupport.class,
                "Function pointer parse failed for synthetic '" + synthetic + "': " + e.getMessage());
            return null;
        }
    }

    private static String allocateTypedefName(DataTypeManager dtm, AtomicInteger seq) {
        for (int attempt = 0; attempt < 10_000; attempt++) {
            String name = "zenyard_fnptr_td_" + seq.getAndIncrement();
            if (dtm.getDataType(ZENYARD_PROTOTYPES_CATEGORY, name) == null) {
                return name;
            }
        }
        return "zenyard_fnptr_td_" + System.nanoTime();
    }
}
