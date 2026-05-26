package com.zenyard.ghidra.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class FunctionPointerTypeSupportTest {

    @Test
    void normalizeStdIntAliases_rewritesUint32ForParser() {
        assertEquals("void (*)(uint)", FunctionPointerTypeSupport.normalizeStdIntAliasesForSignatureParser(
            "void (*)(uint32_t)"));
        assertEquals("uint", FunctionPointerTypeSupport.normalizeStdIntAliasesForSignatureParser("uint32_t"));
        assertEquals("int, uint, ulonglong",
            FunctionPointerTypeSupport.normalizeStdIntAliasesForSignatureParser(
                "int32_t, uint32_t, uint64_t"));
    }

    @Test
    void annotationLooksLikeAbstractFunctionPointer_detectsStarParen() {
        assertTrue(FunctionPointerTypeSupport.annotationLooksLikeAbstractFunctionPointer(
            "void (*)(uint32_t)"));
        assertFalse(FunctionPointerTypeSupport.annotationLooksLikeAbstractFunctionPointer(
            "struct Foo*"));
    }

    @Test
    void stripTrailingPointerSuffix_removesStarsAndSpaces() {
        assertEquals("void (*)(uint32_t)", FunctionPointerTypeSupport.stripTrailingPointerSuffix(
            "void (*)(uint32_t) *"));
        assertEquals("void (*)(uint32_t)", FunctionPointerTypeSupport.stripTrailingPointerSuffix(
            "void (*)(uint32_t)  **  "));
        assertEquals("int", FunctionPointerTypeSupport.stripTrailingPointerSuffix("int*"));
    }

    @Test
    void tryMatchAt_parsesSimpleAbstractFunctionPointer() {
        String s = "void (*)(uint32_t)";
        FunctionPointerTypeSupport.AbstractFnPtrMatch m =
            FunctionPointerTypeSupport.tryMatchAbstractFunctionPointerAt(s, 0);
        assertNotNull(m);
        assertEquals(0, m.start);
        assertEquals(s.length(), m.end);
        assertEquals("void", m.returnType);
        assertEquals("uint32_t", m.paramListInner);
    }

    @Test
    void tryMatchAt_parsesMultiWordReturnAndParams() {
        String s = "unsigned int (*)(uint32_t, int)";
        FunctionPointerTypeSupport.AbstractFnPtrMatch m =
            FunctionPointerTypeSupport.tryMatchAbstractFunctionPointerAt(s, 0);
        assertNotNull(m);
        assertEquals("unsigned int", m.returnType);
        assertEquals("uint32_t, int", m.paramListInner);
    }

    @Test
    void tryMatchAt_requiresFullSpanForInferenceStyleWholeString() {
        String s = "void (*)(uint32_t)";
        FunctionPointerTypeSupport.AbstractFnPtrMatch m =
            FunctionPointerTypeSupport.tryMatchAbstractFunctionPointerAt(s, 0);
        assertNotNull(m);
        assertEquals(s.length(), m.end);
    }

    @Test
    void findShortestMatch_prefersInnerAbstractFunctionPointer() {
        String s = "void (*)(void (*)(void))";
        FunctionPointerTypeSupport.AbstractFnPtrMatch shortest =
            FunctionPointerTypeSupport.findShortestAbstractFunctionPointerMatch(s);
        assertNotNull(shortest);
        assertEquals("void", shortest.returnType);
        assertEquals("void", shortest.paramListInner);
        String inner = s.substring(shortest.start, shortest.end);
        assertEquals("void (*)(void)", inner);
    }

    @Test
    void findShortestMatch_findsParameterInPrototypeLikeString() {
        String s = "void foo(void (*)(uint32_t) cb)";
        FunctionPointerTypeSupport.AbstractFnPtrMatch m =
            FunctionPointerTypeSupport.findShortestAbstractFunctionPointerMatch(s);
        assertNotNull(m);
        assertEquals("void (*)(uint32_t)", s.substring(m.start, m.end));
        assertEquals("void", m.returnType);
        assertEquals("uint32_t", m.paramListInner);
    }
}
