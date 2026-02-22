package com.zenyard.ghidra.copilot.deepagent;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import dev.langchain4j.langsmith.RunTree;
import dev.langchain4j.langsmith.gen.model.Inputs;
import dev.langchain4j.langsmith.gen.model.Outputs;
import dev.langchain4j.langsmith.gen.model.RunTypeEnum;

/**
 * Thread-safe wrapper around the LangSmith RunTree API for tracing
 * the copilot deep agent lifecycle. All tracing calls are fire-and-forget
 * and wrapped in try-catch so they never block or crash the agent.
 */
public class LangSmithTracer {

    private static final long POST_TIMEOUT_SECONDS = 5;
    private static final int INPUT_TRUNCATE_LENGTH = 8000;

    private final boolean enabled;
    private final String projectName;
    private final String apiKey;
    private final String apiUrl;

    private final ConcurrentHashMap<UUID, RunTree> activeRuns = new ConcurrentHashMap<>();
    private final AtomicInteger planCounter = new AtomicInteger(0);
    private volatile RunTree currentRootRun;

    /**
     * Creates a disabled tracer. Use {@link #LangSmithTracer(String, String, String)} to
     * create an enabled tracer with config values from zenyard.json.
     */
    public LangSmithTracer() {
        this.apiKey = null;
        this.apiUrl = null;
        this.projectName = null;
        this.enabled = false;
    }

    /**
     * Creates a tracer from zenyard.json config values. Tracing is enabled only when
     * {@code apiKey} is non-null and non-blank; if the remaining parameters are absent
     * sensible defaults are used.
     *
     * @param apiKey   langsmith_api_key from zenyard.json (required for tracing)
     * @param endpoint langsmith_endpoint from zenyard.json (nullable, defaults to hosted LangSmith)
     * @param project  langsmith_project from zenyard.json (nullable, defaults to "zenyard-copilot")
     */
    public LangSmithTracer(String apiKey, String endpoint, String project) {
        this.apiKey = apiKey;
        this.apiUrl = endpoint != null && !endpoint.isBlank()
                ? endpoint : "https://api.smith.langchain.com";
        this.projectName = project != null && !project.isBlank()
                ? project : "zenyard-copilot";
        this.enabled = apiKey != null && !apiKey.isBlank();
        if (this.enabled) {
            ghidra.util.Msg.info(this, "LangSmith tracing enabled, project=" + projectName
                    + " endpoint=" + apiUrl);
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Return the current root run for this conversation turn, or null.
     */
    public RunTree getCurrentRoot() {
        return currentRootRun;
    }

    /**
     * Start a root CHAIN trace for a conversation turn.
     */
    public RunTree beginTrace(String name, String userMessage) {
        if (!enabled) {
            return null;
        }
        try {
            planCounter.set(0);
            RunTree.Config config = RunTree.getDefaultConfig()
                    .name(name)
                    .runType(RunTypeEnum.CHAIN)
                    .projectName(projectName)
                    .apiUrl(apiUrl)
                    .apiKey(apiKey)
                    .inputs(Inputs.builder()
                            .data("input", truncate(userMessage))
                            .build())
                    .tags(List.of("copilot", "deepagent"))
                    .build();
            RunTree root = new RunTree(config);
            postRunAsync(root);
            activeRuns.put(root.getId(), root);
            currentRootRun = root;
            return root;
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "LangSmith beginTrace failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Create a child LLM run (for PlanNode / ResponseNode).
     */
    public RunTree beginLlmRun(RunTree parent, String name, String messagesDescription) {
        if (!enabled || parent == null) {
            return null;
        }
        try {
            String resolvedName = name;
            if ("plan".equals(name)) {
                resolvedName = "plan-" + planCounter.incrementAndGet();
            }
            RunTree.Config childConfig = RunTree.getDefaultConfig()
                    .name(resolvedName)
                    .runType(RunTypeEnum.LLM)
                    .inputs(Inputs.builder()
                            .data("messages_summary", truncate(messagesDescription))
                            .build())
                    .build();
            RunTree child = parent.createChild(childConfig);
            postRunAsync(child);
            activeRuns.put(child.getId(), child);
            return child;
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "LangSmith beginLlmRun failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Create a child TOOL run (for ToolNode).
     */
    public RunTree beginToolRun(RunTree parent, String toolName, String arguments) {
        if (!enabled || parent == null) {
            return null;
        }
        try {
            RunTree.Config childConfig = RunTree.getDefaultConfig()
                    .name(toolName)
                    .runType(RunTypeEnum.TOOL)
                    .inputs(Inputs.builder()
                            .data("tool_name", toolName)
                            .data("arguments", truncate(arguments))
                            .build())
                    .build();
            RunTree child = parent.createChild(childConfig);
            postRunAsync(child);
            activeRuns.put(child.getId(), child);
            return child;
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "LangSmith beginToolRun failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Create a child CHAIN run (for subagent invocation).
     */
    public RunTree beginChainRun(RunTree parent, String name, String input) {
        if (!enabled || parent == null) {
            return null;
        }
        try {
            RunTree.Config childConfig = RunTree.getDefaultConfig()
                    .name(name)
                    .runType(RunTypeEnum.CHAIN)
                    .inputs(Inputs.builder()
                            .data("input", truncate(input))
                            .build())
                    .tags(List.of("subagent"))
                    .build();
            RunTree child = parent.createChild(childConfig);
            postRunAsync(child);
            activeRuns.put(child.getId(), child);
            return child;
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "LangSmith beginChainRun failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * End a run with outputs.
     */
    public void endRun(RunTree run, Outputs outputs) {
        if (!enabled || run == null) {
            return;
        }
        try {
            run.end(outputs);
            patchRunAsync(run);
            activeRuns.remove(run.getId());
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "LangSmith endRun failed: " + e.getMessage());
        }
    }

    /**
     * End a run with an error.
     */
    public void endRunWithError(RunTree run, String error) {
        if (!enabled || run == null) {
            return;
        }
        try {
            run.end(null, error);
            patchRunAsync(run);
            activeRuns.remove(run.getId());
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "LangSmith endRunWithError failed: " + e.getMessage());
        }
    }

    /**
     * End the root trace with the final response.
     */
    public void endTrace(RunTree root, String finalResponse) {
        if (!enabled || root == null) {
            return;
        }
        try {
            Outputs outputs = Outputs.builder()
                    .data("output", truncate(finalResponse))
                    .build();
            root.end(outputs);
            patchRunAsync(root);
            activeRuns.remove(root.getId());
            currentRootRun = null;
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "LangSmith endTrace failed: " + e.getMessage());
        }
    }

    /**
     * Build an Outputs object from a simple key-value pair.
     */
    public static Outputs outputsOf(String key, String value) {
        return Outputs.builder()
                .data(key, value != null ? value : "")
                .build();
    }

    /**
     * Build an Outputs object from two key-value pairs.
     */
    public static Outputs outputsOf(String key1, String value1, String key2, String value2) {
        return Outputs.builder()
                .data(key1, value1 != null ? value1 : "")
                .data(key2, value2 != null ? value2 : "")
                .build();
    }

    private void postRunAsync(RunTree run) {
        run.postRun().orTimeout(POST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .exceptionally(ex -> {
                    ghidra.util.Msg.warn(this, "LangSmith postRun failed for "
                            + run.getId() + ": " + ex.getMessage());
                    return null;
                });
    }

    private void patchRunAsync(RunTree run) {
        run.patchRun().orTimeout(POST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .exceptionally(ex -> {
                    ghidra.util.Msg.warn(this, "LangSmith patchRun failed for "
                            + run.getId() + ": " + ex.getMessage());
                    return null;
                });
    }

    private static String truncate(String value) {
        if (value == null) {
            return "";
        }
        if (value.length() <= INPUT_TRUNCATE_LENGTH) {
            return value;
        }
        return value.substring(0, INPUT_TRUNCATE_LENGTH) + "...(truncated, len=" + value.length() + ")";
    }
}
