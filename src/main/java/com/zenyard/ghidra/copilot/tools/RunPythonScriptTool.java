package com.zenyard.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import com.zenyard.ghidra.copilot.storage.CopilotArtifactStorage;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tool to execute Python scripts with full Ghidra API access against the current program.
 * Uses Ghidra's GhidraScriptProvider infrastructure, which delegates to PyGhidra (CPython 3)
 * on Ghidra 11.3+ or Jython on older installations.
 */
public class RunPythonScriptTool {

    private static final int MAX_OUTPUT_LENGTH = 8000;

    private final CopilotToolContext context;

    public RunPythonScriptTool(CopilotToolContext context) {
        this.context = context;
    }

    @Tool(name = "run_python_script",
          value = "Execute a Python script with full Ghidra API access against the current program. "
                + "The script runs inside a GhidraScript context where `currentProgram`, `currentAddress`, "
                + "`toAddr()`, `getFunctionAt()`, and all GhidraScript flat API methods are available. "
                + "Use `print()` to output results. Returns captured stdout/stderr.")
    public String runPythonScript(
            @P("Python source code to execute. Has access to all GhidraScript flat API methods "
             + "and the full Ghidra Java API via Python-Java interop.") String code) {
        Map<String, Object> args = new HashMap<>();
        args.put("code", code.length() > 200 ? code.substring(0, 200) + "..." : code);
        return ToolUtils.executeTool(context, "run_python_script", args, () -> {
            try {
                context.checkCancelled();

                List<String> violations = PythonScriptSandbox.validateStatically(code);
                if (!violations.isEmpty()) {
                    throw new ToolExecutionException(
                        "Script blocked by sandbox — forbidden operations detected:\n- "
                        + String.join("\n- ", violations));
                }

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                String allowedPath = resolveAllowedPath();
                String wrappedCode = wrapCode(code, allowedPath);

                File tempFile = File.createTempFile("copilot_script_", ".py");
                try {
                    Files.write(tempFile.toPath(), wrappedCode.getBytes(StandardCharsets.UTF_8));

                    ResourceFile resourceFile = new ResourceFile(tempFile);
                    GhidraScriptProvider provider = GhidraScriptUtil.getProvider(resourceFile);
                    if (provider == null) {
                        throw new ToolExecutionException(
                            "No Python script provider found. "
                            + "Ensure PyGhidra is installed (Ghidra 11.3+) or Jython is available.");
                    }

                    StringWriter outputWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(outputWriter, true);
                    StringWriter errorOutputWriter = new StringWriter();
                    PrintWriter errorPrintWriter = new PrintWriter(errorOutputWriter, true);

                    GhidraScript script = provider.getScriptInstance(resourceFile, printWriter);

                    TaskMonitor monitor = context.getMonitor();
                    if (monitor == null) {
                        monitor = TaskMonitor.DUMMY;
                    }

                    GhidraState state = new GhidraState(
                        context.getTool(), null, program, null, null, null);

                    ScriptControls controls = new ScriptControls(
                        printWriter, errorPrintWriter, monitor);
                    script.execute(state, controls);

                    printWriter.flush();
                    errorPrintWriter.flush();

                    String stdoutText = outputWriter.toString().stripTrailing();
                    String stderrText = errorOutputWriter.toString().stripTrailing();

                    StringBuilder result = new StringBuilder();
                    if (!stdoutText.isEmpty()) {
                        result.append(stdoutText);
                    }
                    if (!stderrText.isEmpty()) {
                        if (result.length() > 0) {
                            result.append("\n");
                        }
                        result.append("STDERR: ").append(stderrText);
                    }

                    String output = result.toString();

                    if (output.isEmpty()) {
                        return "(Script executed successfully with no output)";
                    }

                    if (output.length() > MAX_OUTPUT_LENGTH) {
                        return output.substring(0, MAX_OUTPUT_LENGTH)
                            + "\n... (output truncated at " + MAX_OUTPUT_LENGTH
                            + " chars, total: " + output.length() + ")";
                    }

                    return output;
                } finally {
                    if (!tempFile.delete()) {
                        tempFile.deleteOnExit();
                    }
                }
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                String msg = e.getMessage();
                if (msg != null && msg.contains("cancelled")) {
                    throw new ToolExecutionException("Script execution was cancelled");
                }
                throw new ToolExecutionException("Python script execution failed: " + msg, e);
            }
        });
    }

    private String resolveAllowedPath() {
        CopilotArtifactStorage storage = context.getArtifactStorage();
        if (storage != null) {
            Path base = storage.getBaseDir();
            if (base != null) {
                return base.toAbsolutePath().toString();
            }
        }
        return null;
    }

    /**
     * Wraps user code with the sandbox preamble and stdout/stderr capture,
     * routing output through GhidraScript's println().
     *
     * @param allowedBasePath filesystem path that {@code open()} is restricted
     *                        to, or {@code null} to disable fs access entirely.
     */
    static String wrapCode(String userCode, String allowedBasePath) {
        String sandboxPreamble = PythonScriptSandbox.generateSandboxPreamble(allowedBasePath);

        String indented = userCode.replace("\n", "\n    ");

        return sandboxPreamble
             + "import sys as _copilot_sys, io as _copilot_io\n"
             + "_copilot_stdout = _copilot_io.StringIO()\n"
             + "_copilot_stderr = _copilot_io.StringIO()\n"
             + "_copilot_old_stdout = _copilot_sys.stdout\n"
             + "_copilot_old_stderr = _copilot_sys.stderr\n"
             + "_copilot_sys.stdout = _copilot_stdout\n"
             + "_copilot_sys.stderr = _copilot_stderr\n"
             + "try:\n"
             + "    " + indented + "\n"
             + "finally:\n"
             + "    _copilot_sys.stdout = _copilot_old_stdout\n"
             + "    _copilot_sys.stderr = _copilot_old_stderr\n"
             + "_copilot_out = _copilot_stdout.getvalue()\n"
             + "_copilot_err = _copilot_stderr.getvalue()\n"
             + "if _copilot_out:\n"
             + "    println(_copilot_out.rstrip())\n"
             + "if _copilot_err:\n"
             + "    println('STDERR: ' + _copilot_err.rstrip())\n";
    }

    /**
     * Check whether a Python script provider (PyGhidra or Jython) is available.
     */
    public static boolean isPythonAvailable() {
        try {
            File tempFile = File.createTempFile("copilot_pycheck_", ".py");
            try {
                ResourceFile resourceFile = new ResourceFile(tempFile);
                GhidraScriptProvider provider = GhidraScriptUtil.getProvider(resourceFile);
                return provider != null;
            } finally {
                if (!tempFile.delete()) {
                    tempFile.deleteOnExit();
                }
            }
        } catch (Exception e) {
            Msg.warn(RunPythonScriptTool.class,
                "Failed to check Python availability: " + e.getMessage());
            return false;
        }
    }
}
