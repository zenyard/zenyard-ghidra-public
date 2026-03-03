# Zenyard for Ghidra

**In-depth binary understanding with a purpose-built AI agent that helps you get straight to the meaningful parts and understand them faster.**

Zenyard is a Ghidra extension that brings AI-powered reverse engineering directly into your workflow. It automatically analyzes binaries, renames functions and variables with meaningful identifiers, infers types and structures, and provides an interactive AI copilot that understands your binary at a deep level.

## Features

### Illuminator — Automated Binary Understanding

The Illuminator is Zenyard's analysis engine. When you open a binary, it works in the background to transform raw decompiled code into something you can actually read.

**Function and Variable Renaming**
Zenyard infers meaningful names for functions, local variables, parameters, and global data labels — replacing cryptic defaults like `FUN_00401000`, `uVar1`, and `DAT_00405000` with descriptive identifiers. Renamed symbols are visually highlighted throughout Ghidra's listing, decompiler, function list, and symbol tree so you can instantly tell what's been analyzed.

**Type and Structure Recovery**
Beyond names, the Illuminator infers parameter types, return types, and reconstructs struct definitions. Recovered structures are created in Ghidra's data type manager and propagated through the decompiler output, giving you a clearer picture of how data flows through the binary.

**Function Overviews**
Each analyzed function receives a natural-language summary added as a plate comment at its entry point. These overviews appear in both the listing and decompiler views, giving you a quick read on what a function does without having to trace through the code.

**Incremental Analysis**
Zenyard tracks changes you make to the program and can re-analyze affected functions when you're ready. The status bar indicates when updates are available, and you can trigger re-analysis with a single click.

### CoPilot — Interactive AI Assistant

The CoPilot is a conversational AI assistant embedded directly in Ghidra. It has full access to your binary's context and can reason across functions, data, and control flow to answer your questions.

**Deep Binary Context**
The CoPilot doesn't just see the function you're looking at — it can decompile any function, trace cross-references, inspect strings, examine imports and exports, read memory, and navigate the full symbol table. It builds understanding by actively exploring the binary as it works through your questions.

**Multi-Step Reasoning**
Powered by an AI agent architecture, the CoPilot plans and executes multi-step analysis workflows. It can decompose complex questions, delegate to specialized sub-agents, and synthesize findings — going well beyond simple Q&A to perform actual investigative work.

**Function References**
Use `@` mentions in the chat to reference specific functions by name. The CoPilot resolves these to their addresses and can immediately pull up decompilation, cross-references, or other relevant context.

**Tool Access**
The CoPilot has access to over 30 built-in tools spanning decompilation, cross-reference analysis, string search, symbol lookup, stack frame inspection, basic block enumeration, and more. On systems with PyGhidra, it can also write and execute Python scripts for custom analysis.

**Open the CoPilot:** `Zenyard → Copilot` or <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>C</kbd> (<kbd>Cmd</kbd>+<kbd>Shift</kbd>+<kbd>C</kbd> on macOS).

### Status Bar

The integrated status bar keeps you informed at a glance:

- **Analysis progress** — See what Zenyard is currently doing (uploading, analyzing, applying results) with a live progress indicator.
- **Usage tracking** — Monitor your plan usage directly from the status bar. Click it for detailed plan and quota information.
- **Connectivity status** — Warnings appear automatically if the Zenyard service is unreachable, with automatic reconnection.
- **Action prompts** — Contextual prompts appear when actions are available, such as initial analysis or re-analysis after edits.

## Requirements

- Ghidra 12.x
- Java 21 or later
- Network access to the Zenyard API

## Installation

### From a Release

1. Download the extension ZIP for your platform from the [releases page](https://github.com/zenyard/decompai-ghidra/releases).
2. In Ghidra, go to `File → Install Extensions` and select the ZIP file. Alternatively, extract it into `$GHIDRA_INSTALL_DIR/Ghidra/Extensions/`.
3. Restart Ghidra.

### Building from Source

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew buildExtension
```

The output ZIP is placed in `dist/`. Platform-specific builds (Linux, Windows, macOS Intel/ARM) are supported — see [docs/DEVELOPER.md](docs/DEVELOPER.md) for cross-compilation details.

### Activating the Plugin

After installation, if the plugin doesn't appear automatically:

1. Open the **CodeBrowser** tool.
2. Go to `File → Configure → Miscellaneous`.
3. Enable **ZenyardGhidraPlugin**.

## Getting Started

### First Launch

On first use, Zenyard walks you through a short onboarding:

1. **Terms of Use** — Review and accept the terms.
2. **Configuration** — Enter your API key and server URL, then verify the connection.

### Analyzing a Binary

1. Open a binary in Ghidra and let Ghidra's auto-analysis complete.
2. Zenyard prompts you to start analysis. Optionally, provide context about the binary (its origin, purpose, or known structure) to improve results.
3. Analysis runs in the background — the status bar shows progress in real time.
4. As results arrive, functions and variables are renamed, types are inferred, and overviews are added directly in the listing and decompiler views.

Renamed functions are highlighted with a distinct background color in the function list and symbol tree, making it easy to see analysis coverage at a glance.

### Using the CoPilot

Open the CoPilot panel and start asking questions:

- *"What does this binary do at a high level?"*
- *"Trace the authentication flow starting from main."*
- *"What data structures are used in the network handler?"*
- *"Explain what happens when this function receives a null pointer."*

Use `@functionName` to direct the CoPilot's attention to specific functions. The CoPilot tracks tasks and progress visually, so you can follow along as it works through complex analysis.

## Configuration

Configuration is stored in `~/.ghidra/zenyard.json` and persists across sessions.

| Setting | Description |
|---------|-------------|
| **API Key** | Your Zenyard API key |
| **Server URL** | Zenyard API endpoint (default: `https://api.zenyard.ai`) |
| **SSL Verification** | Toggle SSL/TLS certificate verification |
| **Log Level** | Logging verbosity (DEBUG, INFO, WARN, ERROR) |

Access configuration at any time via `Zenyard → Configuration`.

## Platform Support

The extension includes platform-specific JavaFX WebView libraries. Pre-built packages are available for:

| Platform | Architecture |
|----------|-------------|
| macOS | Intel (x64), Apple Silicon (ARM64) |
| Linux | x64, ARM64 |
| Windows | x64 |

## Usage Plans

Zenyard offers both free and paid plans. Your current usage is always visible in the status bar. When a plan limit is reached, analysis pauses automatically — the CoPilot and previously applied results remain available. Click the usage indicator for plan details or to upgrade.

Binary size limits may apply depending on your plan. If a binary exceeds your plan's limit, a prompt will guide you to the appropriate plan.

## Support

- **Email:** [access@zenyard.ai](mailto:access@zenyard.ai)
- **Issues:** [GitHub Issues](https://github.com/zenyard/decompai-ghidra-public/issues)

