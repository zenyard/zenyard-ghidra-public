package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Multi-layered sandbox for Python scripts executed by {@link RunPythonScriptTool}.
 *
 * Layer 1 – Static validation (Java-side): fast regex checks that reject scripts
 * containing forbidden import or call patterns before any code is written to disk.
 *
 * Layer 2 – Runtime sandbox preamble (Python-side): a block of Python code prepended
 * to every script that installs import hooks, restricts {@code open()}, and overrides
 * dangerous builtins at execution time, catching dynamic or obfuscated bypasses that
 * static checks miss.
 *
 * Threat model: prevent the AI agent from inadvertently generating harmful code, and
 * defend against prompt-injection attacks embedded in analysed binaries that try to
 * trick the agent into producing exfiltration / destructive scripts.
 */
public final class PythonScriptSandbox {

    private PythonScriptSandbox() {}

    // ── Forbidden module / package lists ──────────────────────────────────────

    static final Set<String> FORBIDDEN_PYTHON_MODULES = Set.of(
        "socket",
        "urllib",
        "urllib2",
        "urllib3",
        "http",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
        "poplib",
        "imaplib",
        "xmlrpc",
        "xmlrpclib",
        "subprocess",
        "commands",
        "multiprocessing",
        // importlib stays blocked: importlib.import_module() bypasses the
        // builtins.__import__ hook, allowing forbidden modules to be loaded.
        "importlib"
    );

    static final List<String> FORBIDDEN_JAVA_PREFIXES = List.of(
        "java.net.",
        "java.net",
        "javax.net.",
        "javax.net",
        "java.lang.Runtime",
        "java.lang.ProcessBuilder"
    );

    // ── Dangerous os / builtin call patterns ─────────────────────────────────

    private static final List<Pattern> FORBIDDEN_CALL_PATTERNS = List.of(
        Pattern.compile("\\bos\\.system\\s*\\("),
        Pattern.compile("\\bos\\.popen\\s*\\("),
        Pattern.compile("\\bos\\.exec[velp]*\\s*\\("),
        Pattern.compile("\\bos\\.spawn[velp]*\\s*\\("),
        Pattern.compile("\\bos\\.fork\\s*\\("),
        Pattern.compile("\\bRuntime\\s*\\.\\s*(?:getRuntime\\s*\\(\\s*\\)\\s*\\.\\s*)?exec\\s*\\("),
        Pattern.compile("\\bProcessBuilder\\s*\\(")
    );

    // ── Forbidden Java I/O classes (bypass of Python-level open restriction) ─

    private static final List<String> FORBIDDEN_JAVA_IO = List.of(
        "java.io.FileWriter",
        "java.io.FileOutputStream",
        "java.io.FileInputStream",
        "java.io.RandomAccessFile",
        "java.nio.file.Files"
    );

    // ── Static import patterns ─────────────────────────────────────────────

    /** Matches {@code import X} and the module part of {@code from X import Y}. */
    private static final Pattern IMPORT_PATTERN =
        Pattern.compile("(?:^|;)\\s*(?:import|from)\\s+([\\w.]+)", Pattern.MULTILINE);

    /** Matches {@code from X import Y} capturing both X and Y. */
    private static final Pattern FROM_IMPORT_PATTERN =
        Pattern.compile("(?:^|;)\\s*from\\s+([\\w.]+)\\s+import\\s+([\\w.]+)", Pattern.MULTILINE);

    // ── Layer 1: static validation ───────────────────────────────────────────

    /**
     * Scan the raw Python source for forbidden patterns.
     *
     * @return list of human-readable violation descriptions; empty means the
     *         script passed static validation.
     */
    public static List<String> validateStatically(String code) {
        if (code == null || code.isBlank()) {
            return List.of();
        }

        List<String> violations = new ArrayList<>();

        String stripped = stripCommentsAndStrings(code);

        Matcher importMatcher = IMPORT_PATTERN.matcher(stripped);
        while (importMatcher.find()) {
            String moduleName = importMatcher.group(1);
            checkModuleName(moduleName, violations);
        }

        Matcher fromImportMatcher = FROM_IMPORT_PATTERN.matcher(stripped);
        while (fromImportMatcher.find()) {
            String pkg = fromImportMatcher.group(1);
            String name = fromImportMatcher.group(2);
            checkModuleName(pkg + "." + name, violations);
        }

        for (Pattern cp : FORBIDDEN_CALL_PATTERNS) {
            if (cp.matcher(stripped).find()) {
                violations.add("Forbidden call pattern: " + cp.pattern());
            }
        }

        for (String javaIo : FORBIDDEN_JAVA_IO) {
            String className = javaIo.contains(".")
                ? javaIo.substring(javaIo.lastIndexOf('.') + 1) : javaIo;
            if (stripped.contains(className + "(")) {
                violations.add("Forbidden Java I/O usage: " + javaIo);
            }
        }

        return violations;
    }

    private static void checkModuleName(String moduleName, List<String> violations) {
        String topLevel = moduleName.contains(".")
            ? moduleName.substring(0, moduleName.indexOf('.'))
            : moduleName;

        if (FORBIDDEN_PYTHON_MODULES.contains(topLevel)) {
            violations.add("Forbidden Python module: " + moduleName);
        }

        for (String prefix : FORBIDDEN_JAVA_PREFIXES) {
            if (moduleName.equals(prefix) || moduleName.startsWith(prefix + ".") ||
                (prefix.endsWith(".") && moduleName.startsWith(prefix))) {
                violations.add("Forbidden Java package: " + moduleName);
                break;
            }
        }

        for (String javaIo : FORBIDDEN_JAVA_IO) {
            if (moduleName.equals(javaIo) || moduleName.startsWith(javaIo + ".")) {
                violations.add("Forbidden Java I/O class: " + moduleName);
                break;
            }
        }
    }

    /**
     * Strip single-line comments ({@code #…}) and string literals from Python
     * source so that forbidden keywords inside comments or strings do not
     * trigger false positives.
     */
    static String stripCommentsAndStrings(String code) {
        StringBuilder sb = new StringBuilder(code.length());
        int i = 0;
        int len = code.length();

        while (i < len) {
            char c = code.charAt(i);

            if (c == '#') {
                while (i < len && code.charAt(i) != '\n') {
                    i++;
                }
                continue;
            }

            if (c == '\'' || c == '"') {
                boolean triple = (i + 2 < len
                    && code.charAt(i + 1) == c
                    && code.charAt(i + 2) == c);
                if (triple) {
                    i += 3;
                    while (i < len) {
                        if (code.charAt(i) == c && i + 2 < len
                            && code.charAt(i + 1) == c
                            && code.charAt(i + 2) == c) {
                            i += 3;
                            break;
                        }
                        if (code.charAt(i) == '\\') {
                            i++;
                        }
                        i++;
                    }
                } else {
                    char quote = c;
                    i++;
                    while (i < len && code.charAt(i) != quote) {
                        if (code.charAt(i) == '\\') {
                            i++;
                        }
                        i++;
                    }
                    if (i < len) {
                        i++;
                    }
                }
                sb.append("\"\"");
                continue;
            }

            sb.append(c);
            i++;
        }

        return sb.toString();
    }

    // ── Layer 2: runtime sandbox preamble ────────────────────────────────────

    /**
     * Generate a Python code preamble that installs runtime sandbox
     * restrictions. The preamble is prepended to the wrapped user script.
     *
     * @param allowedBasePath absolute filesystem path that {@code open()} is
     *                        restricted to, or {@code null} to disable fs
     *                        access entirely.
     */
    public static String generateSandboxPreamble(String allowedBasePath) {
        String escapedPath = allowedBasePath != null
            ? allowedBasePath.replace("\\", "\\\\").replace("'", "\\'")
            : "";
        boolean fsEnabled = allowedBasePath != null && !allowedBasePath.isEmpty();

        StringBuilder sb = new StringBuilder(2048);

        sb.append("# ── Copilot sandbox preamble ──\n");

        sb.append("import sys as _sb_sys, os as _sb_os, builtins as _sb_builtins\n");

        // Forbidden module set
        sb.append("_sb_forbidden_modules = frozenset({");
        boolean first = true;
        for (String mod : FORBIDDEN_PYTHON_MODULES) {
            if (!first) sb.append(", ");
            sb.append("'").append(mod).append("'");
            first = false;
        }
        sb.append("})\n");

        // Forbidden Java prefixes
        sb.append("_sb_forbidden_java = (");
        first = true;
        for (String prefix : FORBIDDEN_JAVA_PREFIXES) {
            if (!first) sb.append(", ");
            sb.append("'").append(prefix).append("'");
            first = false;
        }
        sb.append(")\n");

        // Custom __import__ hook
        sb.append("""
            _sb_orig_import = _sb_builtins.__import__
            def _sb_safe_import(name, *args, **kwargs):
                _top = name.split(".")[0]
                if _top in _sb_forbidden_modules:
                    raise RuntimeError("Sandbox: import of '" + name + "' is blocked (forbidden module)")
                for _pfx in _sb_forbidden_java:
                    if name == _pfx or name.startswith(_pfx + ".") or (_pfx.endswith(".") and name.startswith(_pfx)):
                        raise RuntimeError("Sandbox: import of '" + name + "' is blocked (forbidden Java package)")
                return _sb_orig_import(name, *args, **kwargs)
            _sb_builtins.__import__ = _sb_safe_import
            """);

        // Restricted open()
        if (fsEnabled) {
            sb.append("_sb_allowed_base = _sb_os.path.realpath('").append(escapedPath).append("')\n");
            sb.append("""
                _sb_orig_open = _sb_builtins.open
                def _sb_safe_open(file, mode='r', *a, **kw):
                    _resolved = _sb_os.path.realpath(str(file))
                    if not _resolved.startswith(_sb_allowed_base + _sb_os.sep) and _resolved != _sb_allowed_base:
                        raise RuntimeError("Sandbox: file access outside allowed path: " + str(file))
                    return _sb_orig_open(file, mode, *a, **kw)
                _sb_builtins.open = _sb_safe_open
                open = _sb_safe_open
                """);
        } else {
            sb.append("""
                def _sb_no_open(*a, **kw):
                    raise RuntimeError("Sandbox: file access is not permitted")
                _sb_builtins.open = _sb_no_open
                open = _sb_no_open
                """);
        }

        // Block exec/eval/compile in the module namespace only.
        // We must NOT override builtins.exec or builtins.compile because
        // Python's import machinery relies on them internally.
        sb.append("""
            def _sb_blocked_exec(*a, **kw):
                raise RuntimeError("Sandbox: exec() is blocked")
            def _sb_blocked_eval(*a, **kw):
                raise RuntimeError("Sandbox: eval() is blocked")
            def _sb_blocked_compile(*a, **kw):
                raise RuntimeError("Sandbox: compile() is blocked")
            exec = _sb_blocked_exec
            eval = _sb_blocked_eval
            compile = _sb_blocked_compile
            """);

        // Block dangerous os functions if os is already imported
        sb.append("""
            for _sb_attr in ('system', 'popen', 'execl', 'execle', 'execlp', 'execlpe',
                             'execv', 'execve', 'execvp', 'execvpe', 'spawnl', 'spawnle',
                             'spawnlp', 'spawnlpe', 'spawnv', 'spawnve', 'spawnvp',
                             'spawnvpe', 'fork', 'forkpty', 'killpg', 'popen2', 'popen3', 'popen4'):
                if hasattr(_sb_os, _sb_attr):
                    setattr(_sb_os, _sb_attr, lambda *a, _n=_sb_attr, **kw: (_ for _ in ()).throw(
                        RuntimeError("Sandbox: os." + _n + "() is blocked")))
            del _sb_attr
            """);

        sb.append("# ── end sandbox preamble ──\n");

        return sb.toString();
    }
}
