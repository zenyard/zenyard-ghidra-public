package com.zenyard.ghidra.copilot.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PythonScriptSandboxTest {

    // ── Static validation: forbidden Python imports ──────────────────────────

    @Nested
    class ForbiddenPythonImports {

        @ParameterizedTest
        @ValueSource(strings = {
            "import socket",
            "import  socket",
            "from socket import AF_INET",
            "import urllib.request",
            "from urllib import request",
            "import http.client",
            "from http.server import HTTPServer",
            "import requests",
            "import subprocess",
            "from subprocess import Popen",
            "import multiprocessing",
            "import importlib",
            "from importlib import import_module",
            "import ftplib",
            "import smtplib",
            "import poplib",
            "import imaplib",
            "import xmlrpc.client",
            "import aiohttp",
            "import httpx",
            "import commands",
        })
        void rejectsBlockedModule(String importLine) {
            String code = "x = 1\n" + importLine + "\nprint(x)";
            List<String> violations = PythonScriptSandbox.validateStatically(code);
            assertFalse(violations.isEmpty(),
                "Expected violation for: " + importLine);
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "import ghidra.program.model",
            "from ghidra.app.decompiler import DecompInterface",
            "import os",
            "from os.path import join",
            "import re",
            "import json",
            "import struct",
            "import collections",
            "import sys",
            "import io",
            "import math",
            "import hashlib",
            "import binascii",
            "import ctypes",
            "from ctypes import Structure",
        })
        void allowsSafeModule(String importLine) {
            String code = importLine + "\nprint('ok')";
            List<String> violations = PythonScriptSandbox.validateStatically(code);
            assertTrue(violations.isEmpty(),
                "Unexpected violation for: " + importLine + " -> " + violations);
        }
    }

    // ── Static validation: forbidden Java imports ────────────────────────────

    @Nested
    class ForbiddenJavaImports {

        @ParameterizedTest
        @ValueSource(strings = {
            "from java.net import Socket",
            "import java.net.URL",
            "from javax.net.ssl import SSLSocketFactory",
            "import java.lang.Runtime",
            "from java.lang import ProcessBuilder",
        })
        void rejectsBlockedJavaPackage(String importLine) {
            List<String> violations = PythonScriptSandbox.validateStatically(importLine);
            assertFalse(violations.isEmpty(),
                "Expected violation for: " + importLine);
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "from java.util import ArrayList",
            "import java.lang.String",
            "from ghidra.program.model.listing import Function",
        })
        void allowsSafeJavaPackage(String importLine) {
            List<String> violations = PythonScriptSandbox.validateStatically(importLine);
            assertTrue(violations.isEmpty(),
                "Unexpected violation for: " + importLine + " -> " + violations);
        }
    }

    // ── Static validation: forbidden Java I/O classes ────────────────────────

    @Nested
    class ForbiddenJavaIo {

        @ParameterizedTest
        @ValueSource(strings = {
            "from java.io import FileWriter",
            "import java.io.FileOutputStream",
            "import java.io.FileInputStream",
            "import java.nio.file.Files",
        })
        void rejectsBlockedJavaIoImport(String importLine) {
            List<String> violations = PythonScriptSandbox.validateStatically(importLine);
            assertFalse(violations.isEmpty(),
                "Expected violation for: " + importLine);
        }

        @Test
        void rejectsJavaIoClassUsageWithoutImport() {
            String code = "writer = FileWriter('/tmp/evil.txt')";
            List<String> violations = PythonScriptSandbox.validateStatically(code);
            assertFalse(violations.isEmpty(),
                "Expected violation for inline FileWriter usage");
        }
    }

    // ── Static validation: forbidden call patterns ───────────────────────────

    @Nested
    class ForbiddenCallPatterns {

        @ParameterizedTest
        @ValueSource(strings = {
            "os.system('ls')",
            "os.popen('whoami')",
            "os.execl('/bin/sh', 'sh')",
            "os.execve('/bin/sh', [], {})",
            "os.spawnl(os.P_WAIT, '/bin/sh')",
            "os.fork()",
            "ProcessBuilder('cmd')",
        })
        void rejectsDangerousCall(String callExpr) {
            String code = "import os\n" + callExpr;
            List<String> violations = PythonScriptSandbox.validateStatically(code);
            assertFalse(violations.isEmpty(),
                "Expected violation for: " + callExpr);
        }
    }

    // ── Static validation: false-positive avoidance ──────────────────────────

    @Nested
    class FalsePositiveAvoidance {

        @Test
        void ignoresForbiddenWordInComment() {
            String code = "# import socket\nprint('hello')";
            List<String> violations = PythonScriptSandbox.validateStatically(code);
            assertTrue(violations.isEmpty(),
                "Comment should not trigger violation: " + violations);
        }

        @Test
        void ignoresForbiddenWordInString() {
            String code = "msg = 'import socket is dangerous'\nprint(msg)";
            List<String> violations = PythonScriptSandbox.validateStatically(code);
            assertTrue(violations.isEmpty(),
                "String literal should not trigger violation: " + violations);
        }

        @Test
        void ignoresForbiddenWordInTripleQuotedString() {
            String code = "doc = \"\"\"\nimport socket\nfrom subprocess import Popen\n\"\"\"\nprint(doc)";
            List<String> violations = PythonScriptSandbox.validateStatically(code);
            assertTrue(violations.isEmpty(),
                "Triple-quoted string should not trigger violation: " + violations);
        }

        @Test
        void ignoresForbiddenWordInSingleQuoteTripleString() {
            String code = "doc = '''\nimport socket\n'''\nprint(doc)";
            List<String> violations = PythonScriptSandbox.validateStatically(code);
            assertTrue(violations.isEmpty(),
                "Triple-quoted string should not trigger violation: " + violations);
        }

        @Test
        void allowsVariableNamedSocket() {
            String code = "socket_count = 5\nprint(socket_count)";
            List<String> violations = PythonScriptSandbox.validateStatically(code);
            assertTrue(violations.isEmpty(),
                "Variable name 'socket_count' should not trigger: " + violations);
        }
    }

    // ── Static validation: edge cases ────────────────────────────────────────

    @Nested
    class EdgeCases {

        @Test
        void handlesNullCode() {
            assertEquals(List.of(), PythonScriptSandbox.validateStatically(null));
        }

        @Test
        void handlesEmptyCode() {
            assertEquals(List.of(), PythonScriptSandbox.validateStatically(""));
        }

        @Test
        void handlesBlankCode() {
            assertEquals(List.of(), PythonScriptSandbox.validateStatically("   \n\n  "));
        }

        @Test
        void detectsMultipleViolations() {
            String code = "import socket\nimport subprocess\nos.system('ls')";
            List<String> violations = PythonScriptSandbox.validateStatically(code);
            assertTrue(violations.size() >= 3,
                "Expected at least 3 violations, got " + violations.size() + ": " + violations);
        }

        @Test
        void handlesImportAfterSemicolon() {
            String code = "x = 1; import socket";
            List<String> violations = PythonScriptSandbox.validateStatically(code);
            assertFalse(violations.isEmpty(),
                "Semicolon-separated import should be caught");
        }
    }

    // ── stripCommentsAndStrings ──────────────────────────────────────────────

    @Nested
    class StripCommentsAndStrings {

        @Test
        void stripsLineComment() {
            String result = PythonScriptSandbox.stripCommentsAndStrings("x = 1 # import socket\ny = 2");
            assertFalse(result.contains("socket"));
            assertTrue(result.contains("x = 1"));
            assertTrue(result.contains("y = 2"));
        }

        @Test
        void stripsSingleQuotedString() {
            String result = PythonScriptSandbox.stripCommentsAndStrings("x = 'import socket'");
            assertFalse(result.contains("socket"));
        }

        @Test
        void stripsDoubleQuotedString() {
            String result = PythonScriptSandbox.stripCommentsAndStrings("x = \"import socket\"");
            assertFalse(result.contains("socket"));
        }

        @Test
        void stripsTripleQuotedString() {
            String result = PythonScriptSandbox.stripCommentsAndStrings(
                "x = \"\"\"import socket\nfrom subprocess import run\"\"\"");
            assertFalse(result.contains("socket"));
            assertFalse(result.contains("subprocess"));
        }

        @Test
        void handlesEscapedQuotes() {
            String result = PythonScriptSandbox.stripCommentsAndStrings(
                "x = 'it\\'s a \\\"test\\\"'");
            assertFalse(result.contains("test"));
        }

        @Test
        void preservesCodeOutsideStrings() {
            String result = PythonScriptSandbox.stripCommentsAndStrings(
                "import os\nx = 'hello'\nimport re");
            assertTrue(result.contains("import os"));
            assertTrue(result.contains("import re"));
        }
    }

    // ── Sandbox preamble generation ──────────────────────────────────────────

    @Nested
    class SandboxPreamble {

        @Test
        void preambleContainsImportHook() {
            String preamble = PythonScriptSandbox.generateSandboxPreamble("/tmp/artifacts");
            assertTrue(preamble.contains("_sb_safe_import"));
            assertTrue(preamble.contains("_sb_builtins.__import__"));
        }

        @Test
        void preambleContainsForbiddenModules() {
            String preamble = PythonScriptSandbox.generateSandboxPreamble("/tmp/artifacts");
            assertTrue(preamble.contains("'socket'"));
            assertTrue(preamble.contains("'subprocess'"));
            assertFalse(preamble.contains("'ctypes'"));
            assertTrue(preamble.contains("'importlib'"));
        }

        @Test
        void preambleContainsRestrictedOpen() {
            String preamble = PythonScriptSandbox.generateSandboxPreamble("/tmp/artifacts");
            assertTrue(preamble.contains("_sb_safe_open"));
            assertTrue(preamble.contains("/tmp/artifacts"));
        }

        @Test
        void preambleDisablesOpenWhenNoPath() {
            String preamble = PythonScriptSandbox.generateSandboxPreamble(null);
            assertTrue(preamble.contains("_sb_no_open"));
            assertTrue(preamble.contains("file access is not permitted"));
        }

        @Test
        void preambleBlocksExecEvalCompile() {
            String preamble = PythonScriptSandbox.generateSandboxPreamble("/tmp/artifacts");
            assertTrue(preamble.contains("_sb_blocked_exec"));
            assertTrue(preamble.contains("_sb_blocked_eval"));
            assertTrue(preamble.contains("_sb_blocked_compile"));
        }

        @Test
        void preambleBlocksOsFunctions() {
            String preamble = PythonScriptSandbox.generateSandboxPreamble("/tmp/artifacts");
            assertTrue(preamble.contains("'system'"));
            assertTrue(preamble.contains("'popen'"));
            assertTrue(preamble.contains("'fork'"));
        }

        @Test
        void preambleEscapesPathWithBackslashes() {
            String preamble = PythonScriptSandbox.generateSandboxPreamble("C:\\Users\\test\\artifacts");
            assertTrue(preamble.contains("C:\\\\Users\\\\test\\\\artifacts"));
        }
    }
}
