package com.zenyard.ghidra.copilot.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Execution tests that invoke real Python to verify:
 * <ul>
 *   <li>The sandbox preamble is syntactically valid Python 3</li>
 *   <li>Safe scripts (typical agent output) execute correctly inside the sandbox</li>
 *   <li>Forbidden operations are blocked at runtime by the sandbox hooks</li>
 *   <li>File I/O within the allowed artifact directory works</li>
 *   <li>{@link RunPythonScriptTool#wrapCode} produces executable code</li>
 * </ul>
 *
 * All tests are skipped when {@code python3} is not on the PATH.
 */
class PythonScriptSandboxExecutionTest {

    @BeforeAll
    static void requirePython3() {
        assumeTrue(isPython3Available(), "python3 not found on PATH — skipping execution tests");
    }

    // ── Preamble validity ────────────────────────────────────────────────────

    @Nested
    class PreambleSyntax {

        @Test
        void preambleIsValidPythonSyntax(@TempDir Path tmp) throws Exception {
            String preamble = PythonScriptSandbox.generateSandboxPreamble(tmp.toString());
            String parseScript = "import ast, sys\n"
                + "code = open(sys.argv[1]).read()\n"
                + "ast.parse(code)\n"
                + "print('SYNTAX_OK')\n";
            PythonResult result = runPythonWithFile(parseScript, preamble, tmp);
            assertTrue(result.stdout.contains("SYNTAX_OK"),
                "Preamble failed Python AST parse:\n" + result.combinedOutput());
        }

        @Test
        void preambleExecutesWithoutError(@TempDir Path tmp) throws Exception {
            String preamble = PythonScriptSandbox.generateSandboxPreamble(tmp.toString());
            String code = preamble + "print('PREAMBLE_OK')\n";
            PythonResult result = runPython(code, tmp);
            assertEquals(0, result.exitCode,
                "Preamble execution failed:\n" + result.combinedOutput());
            assertTrue(result.stdout.contains("PREAMBLE_OK"));
        }

        @Test
        void preambleWithNullPathExecutes(@TempDir Path tmp) throws Exception {
            String preamble = PythonScriptSandbox.generateSandboxPreamble(null);
            String code = preamble + "print('NULL_PATH_OK')\n";
            PythonResult result = runPython(code, tmp);
            assertEquals(0, result.exitCode,
                "Preamble with null path failed:\n" + result.combinedOutput());
            assertTrue(result.stdout.contains("NULL_PATH_OK"));
        }
    }

    // ── Safe operations pass through sandbox ─────────────────────────────────

    @Nested
    class SafeOperations {

        @Test
        void printWorks(@TempDir Path tmp) throws Exception {
            assertSandboxedOutput(tmp, "print('hello_sandbox')", "hello_sandbox");
        }

        @Test
        void mathOperationsWork(@TempDir Path tmp) throws Exception {
            assertSandboxedOutput(tmp,
                "import math\nprint(math.factorial(5))", "120");
        }

        @Test
        void jsonModuleWorks(@TempDir Path tmp) throws Exception {
            assertSandboxedOutput(tmp,
                "import json\nprint(json.dumps({'a': 1}))", "{\"a\": 1}");
        }

        @Test
        void reModuleWorks(@TempDir Path tmp) throws Exception {
            assertSandboxedOutput(tmp,
                "import re\nm = re.search(r'([0-9a-f]{6,})', 'addr_0x401000')\nprint(m.group(1))",
                "401000");
        }

        @Test
        void structModuleWorks(@TempDir Path tmp) throws Exception {
            assertSandboxedOutput(tmp,
                "import struct\nprint(struct.pack('>I', 0xDEADBEEF).hex())", "deadbeef");
        }

        @Test
        void osPathOperationsWork(@TempDir Path tmp) throws Exception {
            assertSandboxedOutput(tmp,
                "import os.path\nprint(os.path.join('a', 'b'))", "a/b");
        }

        @Test
        void collectionsModuleWorks(@TempDir Path tmp) throws Exception {
            assertSandboxedOutput(tmp,
                "from collections import Counter\nc = Counter('aabbc')\nprint(c['a'])", "2");
        }

        @Test
        void hashlibModuleWorks(@TempDir Path tmp) throws Exception {
            assertSandboxedOutput(tmp,
                "import hashlib\nprint(hashlib.md5(b'test').hexdigest())",
                "098f6bcd4621d373cade4e832627b4f6");
        }

        @Test
        void binasciiModuleWorks(@TempDir Path tmp) throws Exception {
            assertSandboxedOutput(tmp,
                "import binascii\nprint(binascii.hexlify(b'AB').decode())", "4142");
        }

        @Test
        void multilineScriptWorks(@TempDir Path tmp) throws Exception {
            String script = """
                results = []
                for i in range(5):
                    results.append(i * i)
                print(results)
                """;
            assertSandboxedOutput(tmp, script, "[0, 1, 4, 9, 16]");
        }

        @Test
        void stringManipulationWorks(@TempDir Path tmp) throws Exception {
            assertSandboxedOutput(tmp,
                "s = 'FUN_00401000'\nprint(s.replace('FUN_', '0x'))", "0x00401000");
        }

        @Test
        void ctypesModuleWorks(@TempDir Path tmp) throws Exception {
            assertSandboxedOutput(tmp,
                "import ctypes\nprint(ctypes.sizeof(ctypes.c_uint32))", "4");
        }
    }

    // ── File I/O enforcement ─────────────────────────────────────────────────

    @Nested
    class FileIoEnforcement {

        @Test
        void writeInsideAllowedPathSucceeds(@TempDir Path tmp) throws Exception {
            String script = "f = open('" + escapePath(tmp) + "/output.txt', 'w')\n"
                + "f.write('hello')\n"
                + "f.close()\n"
                + "f2 = open('" + escapePath(tmp) + "/output.txt', 'r')\n"
                + "print(f2.read())\n"
                + "f2.close()\n";
            assertSandboxedOutput(tmp, script, "hello");
            assertTrue(Files.exists(tmp.resolve("output.txt")));
        }

        @Test
        void readInsideAllowedPathSucceeds(@TempDir Path tmp) throws Exception {
            Files.writeString(tmp.resolve("data.txt"), "sandbox_data");
            String script = "f = open('" + escapePath(tmp) + "/data.txt', 'r')\n"
                + "print(f.read())\n"
                + "f.close()\n";
            assertSandboxedOutput(tmp, script, "sandbox_data");
        }

        @Test
        void writeOutsideAllowedPathBlocked(@TempDir Path tmp) throws Exception {
            String script = "open('/tmp/evil_sandbox_test.txt', 'w')";
            PythonResult result = runSandboxed(tmp, script);
            assertNotEquals(0, result.exitCode,
                "Expected failure for file access outside sandbox");
            assertTrue(result.combinedOutput().contains("Sandbox"),
                "Expected sandbox error message, got:\n" + result.combinedOutput());
        }

        @Test
        void readOutsideAllowedPathBlocked(@TempDir Path tmp) throws Exception {
            String script = "open('/etc/passwd', 'r')";
            PythonResult result = runSandboxed(tmp, script);
            assertNotEquals(0, result.exitCode,
                "Expected failure for file access outside sandbox");
            assertTrue(result.combinedOutput().contains("Sandbox"),
                "Expected sandbox error, got:\n" + result.combinedOutput());
        }

        @Test
        void fileAccessDisabledWhenNoPath(@TempDir Path tmp) throws Exception {
            String preamble = PythonScriptSandbox.generateSandboxPreamble(null);
            String script = preamble + "open('anything.txt', 'r')\n";
            PythonResult result = runPython(script, tmp);
            assertNotEquals(0, result.exitCode);
            assertTrue(result.combinedOutput().contains("not permitted"),
                "Expected 'not permitted', got:\n" + result.combinedOutput());
        }
    }

    // ── Forbidden imports blocked at runtime ─────────────────────────────────

    @Nested
    class RuntimeImportBlocking {

        @Test
        void socketImportBlocked(@TempDir Path tmp) throws Exception {
            assertRuntimeBlocked(tmp, "import socket", "socket");
        }

        @Test
        void subprocessImportBlocked(@TempDir Path tmp) throws Exception {
            assertRuntimeBlocked(tmp, "import subprocess", "subprocess");
        }

        @Test
        void urllibImportBlocked(@TempDir Path tmp) throws Exception {
            assertRuntimeBlocked(tmp, "import urllib.request", "urllib");
        }

        @Test
        void httpClientImportBlocked(@TempDir Path tmp) throws Exception {
            assertRuntimeBlocked(tmp, "import http.client", "http");
        }

        @Test
        void multiprocessingImportBlocked(@TempDir Path tmp) throws Exception {
            assertRuntimeBlocked(tmp, "import multiprocessing", "multiprocessing");
        }

        @Test
        void requestsImportBlocked(@TempDir Path tmp) throws Exception {
            assertRuntimeBlocked(tmp, "import requests", "requests");
        }
    }

    // ── Dangerous builtins blocked at runtime ────────────────────────────────

    @Nested
    class RuntimeBuiltinBlocking {

        @Test
        void execBlocked(@TempDir Path tmp) throws Exception {
            PythonResult result = runSandboxed(tmp, "exec('print(1)')");
            assertNotEquals(0, result.exitCode);
            assertTrue(result.combinedOutput().contains("Sandbox"),
                "Expected sandbox error, got:\n" + result.combinedOutput());
        }

        @Test
        void evalBlocked(@TempDir Path tmp) throws Exception {
            PythonResult result = runSandboxed(tmp, "eval('1+1')");
            assertNotEquals(0, result.exitCode);
            assertTrue(result.combinedOutput().contains("Sandbox"),
                "Expected sandbox error, got:\n" + result.combinedOutput());
        }

        @Test
        void osSystemBlocked(@TempDir Path tmp) throws Exception {
            PythonResult result = runSandboxed(tmp, "import os\nos.system('echo pwned')");
            assertNotEquals(0, result.exitCode);
            assertTrue(result.combinedOutput().contains("Sandbox"),
                "Expected sandbox error for os.system, got:\n" + result.combinedOutput());
        }

        @Test
        void osForkBlocked(@TempDir Path tmp) throws Exception {
            PythonResult result = runSandboxed(tmp, "import os\nos.fork()");
            assertNotEquals(0, result.exitCode);
            assertTrue(result.combinedOutput().contains("Sandbox"),
                "Expected sandbox error for os.fork, got:\n" + result.combinedOutput());
        }
    }

    // ── wrapCode integration ─────────────────────────────────────────────────

    @Nested
    class WrapCodeIntegration {

        @Test
        void wrappedCodeContainsSandboxPreamble() {
            String wrapped = RunPythonScriptTool.wrapCode("print('hi')", "/tmp/art");
            assertTrue(wrapped.contains("_sb_safe_import"),
                "Wrapped code should contain sandbox import hook");
            assertTrue(wrapped.contains("_sb_forbidden_modules"),
                "Wrapped code should contain forbidden module set");
        }

        @Test
        void wrappedCodeContainsUserCode() {
            String wrapped = RunPythonScriptTool.wrapCode("x = 42\nprint(x)", "/tmp/art");
            assertTrue(wrapped.contains("x = 42"));
            assertTrue(wrapped.contains("print(x)"));
        }

        @Test
        void wrappedCodeExecutesAndProducesOutput(@TempDir Path tmp) throws Exception {
            String wrapped = RunPythonScriptTool.wrapCode("print('wrapped_output')", tmp.toString());
            String withStub = "def println(s): print(s)\n" + wrapped;
            PythonResult result = runPython(withStub, tmp);
            assertEquals(0, result.exitCode,
                "Wrapped code execution failed:\n" + result.combinedOutput());
            assertTrue(result.stdout.contains("wrapped_output"),
                "Expected output not found in:\n" + result.stdout);
        }

        @Test
        void wrappedMathScriptExecutes(@TempDir Path tmp) throws Exception {
            String userCode = "import math\nresult = math.sqrt(144)\nprint(int(result))";
            String wrapped = RunPythonScriptTool.wrapCode(userCode, tmp.toString());
            String withStub = "def println(s): print(s)\n" + wrapped;
            PythonResult result = runPython(withStub, tmp);
            assertEquals(0, result.exitCode,
                "Wrapped math script failed:\n" + result.combinedOutput());
            assertTrue(result.stdout.contains("12"),
                "Expected '12' in output:\n" + result.stdout);
        }

        @Test
        void wrappedScriptBlocksForbiddenImport(@TempDir Path tmp) throws Exception {
            String wrapped = RunPythonScriptTool.wrapCode("import socket", tmp.toString());
            String withStub = "def println(s): print(s)\n" + wrapped;
            PythonResult result = runPython(withStub, tmp);
            assertNotEquals(0, result.exitCode,
                "Wrapped code should have blocked socket import");
            assertTrue(result.combinedOutput().contains("Sandbox"),
                "Expected sandbox error:\n" + result.combinedOutput());
        }

        @Test
        void wrappedScriptBlocksFileOutsidePath(@TempDir Path tmp) throws Exception {
            String wrapped = RunPythonScriptTool.wrapCode(
                "open('/tmp/evil_test.txt', 'w')", tmp.toString());
            String withStub = "def println(s): print(s)\n" + wrapped;
            PythonResult result = runPython(withStub, tmp);
            assertNotEquals(0, result.exitCode,
                "Wrapped code should have blocked file outside sandbox");
            assertTrue(result.combinedOutput().contains("Sandbox"),
                "Expected sandbox error:\n" + result.combinedOutput());
        }

        @Test
        void wrappedScriptAllowsFileInsidePath(@TempDir Path tmp) throws Exception {
            String userCode = "f = open('" + escapePath(tmp) + "/test.txt', 'w')\n"
                + "f.write('from_wrapped')\n"
                + "f.close()\n"
                + "print('write_ok')";
            String wrapped = RunPythonScriptTool.wrapCode(userCode, tmp.toString());
            String withStub = "def println(s): print(s)\n" + wrapped;
            PythonResult result = runPython(withStub, tmp);
            assertEquals(0, result.exitCode,
                "Wrapped code file write failed:\n" + result.combinedOutput());
            assertTrue(result.stdout.contains("write_ok"));
            assertEquals("from_wrapped", Files.readString(tmp.resolve("test.txt")));
        }

        @Test
        void wrappedMultiStepAnalysisScript(@TempDir Path tmp) throws Exception {
            String userCode = """
                import json
                import re
                import os.path

                data = {'functions': ['main', 'init', 'cleanup'], 'count': 3}
                json_str = json.dumps(data)
                matches = re.findall(r'"(\\w+)"', json_str)
                joined = os.path.join('analysis', 'results.txt')
                print(f"found {len(matches)} matches, path={joined}")
                """;
            String wrapped = RunPythonScriptTool.wrapCode(userCode, tmp.toString());
            String withStub = "def println(s): print(s)\n" + wrapped;
            PythonResult result = runPython(withStub, tmp);
            assertEquals(0, result.exitCode,
                "Multi-step script failed:\n" + result.combinedOutput());
            assertTrue(result.stdout.contains("found"),
                "Expected 'found' in output:\n" + result.stdout);
            assertTrue(result.stdout.contains("analysis/results.txt"),
                "Expected path in output:\n" + result.stdout);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static boolean isPython3Available() {
        try {
            Process p = new ProcessBuilder("python3", "--version")
                .redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor(5, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private void assertSandboxedOutput(Path allowedDir, String userCode, String expected)
            throws Exception {
        PythonResult result = runSandboxed(allowedDir, userCode);
        assertEquals(0, result.exitCode,
            "Script failed (exit " + result.exitCode + "):\n" + result.combinedOutput());
        assertTrue(result.stdout.strip().contains(expected),
            "Expected '" + expected + "' in output:\n" + result.stdout);
    }

    private void assertRuntimeBlocked(Path allowedDir, String importStatement, String keyword)
            throws Exception {
        PythonResult result = runSandboxed(allowedDir, importStatement);
        assertNotEquals(0, result.exitCode,
            "Expected failure for: " + importStatement);
        String output = result.combinedOutput();
        assertTrue(output.contains("Sandbox") && output.contains("blocked"),
            "Expected sandbox blocked message for '" + keyword + "', got:\n" + output);
    }

    private PythonResult runSandboxed(Path allowedDir, String userCode) throws Exception {
        String preamble = PythonScriptSandbox.generateSandboxPreamble(allowedDir.toString());
        String fullCode = preamble + userCode + "\n";
        return runPython(fullCode, allowedDir);
    }

    private PythonResult runPython(String code, Path workDir) throws Exception {
        Path script = Files.createTempFile(workDir, "sbtest_", ".py");
        try {
            Files.writeString(script, code, StandardCharsets.UTF_8);
            ProcessBuilder pb = new ProcessBuilder("python3", script.toString());
            pb.directory(workDir.toFile());
            pb.environment().put("PYTHONDONTWRITEBYTECODE", "1");
            Process process = pb.start();
            String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            boolean finished = process.waitFor(15, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                fail("Python process timed out after 15s");
            }
            return new PythonResult(process.exitValue(), stdout, stderr);
        } finally {
            Files.deleteIfExists(script);
        }
    }

    /**
     * Helper for the preamble syntax test: write the preamble to a file, then
     * run a separate script that parses it with {@code ast.parse()}.
     */
    private PythonResult runPythonWithFile(String parserScript, String targetContent, Path workDir)
            throws Exception {
        Path target = Files.createTempFile(workDir, "target_", ".py");
        Path runner = Files.createTempFile(workDir, "runner_", ".py");
        try {
            Files.writeString(target, targetContent, StandardCharsets.UTF_8);
            String fullRunner = parserScript.replace("sys.argv[1]",
                "'" + escapePath(target) + "'");
            Files.writeString(runner, fullRunner, StandardCharsets.UTF_8);
            ProcessBuilder pb = new ProcessBuilder("python3", runner.toString());
            pb.directory(workDir.toFile());
            Process process = pb.start();
            String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            process.waitFor(10, TimeUnit.SECONDS);
            return new PythonResult(process.exitValue(), stdout, stderr);
        } finally {
            Files.deleteIfExists(target);
            Files.deleteIfExists(runner);
        }
    }

    private static String escapePath(Path p) {
        return p.toAbsolutePath().toString().replace("\\", "\\\\").replace("'", "\\'");
    }

    record PythonResult(int exitCode, String stdout, String stderr) {
        String combinedOutput() {
            return stdout + (stderr.isEmpty() ? "" : "\nSTDERR:\n" + stderr);
        }
    }
}
