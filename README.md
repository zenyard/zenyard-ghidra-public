# Zenyard Ghidra Plugin

A Ghidra plugin that provides AI-powered reverse engineering assistance through the Zenyard service.

## Features

### Illuminator
- Function highlighting and renaming
- Variable highlighting and renaming
- Function overview descriptions in disassembly/decompile views
- Execute tools for static analysis

### CoPilot Module
- Copilot window for LLM-assisted interaction (chat)

### Misc
- Status bar UI for displaying analysis progress, errors, and other indications
- External (remote) API interactions with Zenyard API server
- License configuration screen

## Requirements

- Ghidra 12.x (desktop)
- Java 21 or later
- Network access to Zenyard API server

## Installation

### Prerequisites

Before building, you need to set the Ghidra installation directory. You can do this in one of three ways:

1. **Environment variable** (recommended for one-time builds):
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```

2. **Gradle properties** (recommended for persistent configuration):
   Edit `gradle.properties` and uncomment/add:
   ```properties
   GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```

3. **Command line** (for one-time builds):
   ```bash
   ./gradlew -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
   ```

**Note**: The path should point to the directory containing the `Ghidra` folder. For example:
- If Ghidra is at `/Applications/ghidra_11.2/Ghidra/`, use `/Applications/ghidra_11.2`
- If Ghidra is at `/opt/ghidra/Ghidra/`, use `/opt/ghidra`

The build script will attempt to auto-detect common installation locations if `GHIDRA_INSTALL_DIR` is not set.

### Building

The extension embeds JavaFX (WebView) and ships platform-specific native libraries.
Each build produces a ZIP containing JavaFX JARs for **one** target platform.

**Default (build for your current OS/arch):**

```bash
./gradlew buildExtension
```

The build auto-detects your OS and architecture (e.g. `mac-aarch64` on Apple Silicon, `linux` on Linux x64).

**Cross-build for a specific platform:**

```bash
./gradlew -PjavafxPlatform=linux buildExtension    # Linux x64
./gradlew -PjavafxPlatform=win buildExtension      # Windows x64
./gradlew -PjavafxPlatform=mac buildExtension      # macOS Intel
./gradlew -PjavafxPlatform=mac-aarch64 buildExtension  # macOS Apple Silicon
./gradlew -PjavafxPlatform=linux-aarch64 buildExtension # Linux ARM64
```

The `linux-aarch64` platform uses pre-extracted JARs from `third-party/javafx/linux-aarch64/`
(already committed to the repo) since OpenJFX does not publish this classifier to Maven Central.

The output ZIP is in `dist/`.

### Installing

1. Copy the built extension ZIP to `$GHIDRA_INSTALL_DIR/Ghidra/Extensions`, or use Ghidra's extension manager.
2. Open Ghidra, go to `Edit -> Tool Options -> Zenyard`.
3. Enter your API key and server URL, then click "Test Connection" to verify.

## Troubleshooting

### Plugin not available after installation

In some cases, Ghidra installs the extension but does not automatically activate the plugin in the current tool.

To activate it manually:

1. Open the **CodeBrowser** tool window.
2. Go to `File -> Config -> Misc`.
3. Check `ZenyardGhidraPlugin`.
4. Apply/OK the changes (restart the tool if prompted).

## Configuration

The plugin requires:
- **API Key**: Your Zenyard API key
- **Server URL**: The base URL of the Zenyard API server (default: `https://api.zenyard.com`)

Configuration is stored in Ghidra's tool options and persists across sessions.

## Usage

### Initial Analysis

When you open a binary in Ghidra:
1. Wait for Ghidra's initial auto-analysis to complete
2. A dialog will appear asking if you want to start Zenyard analysis
3. Choose your preferences (auto-apply results, allow preprocessing)
4. The plugin will upload the binary and begin analysis in the background

### Manual Analysis

You can also trigger analysis manually:
- Right-click on a function in the listing → "Analyze with Zenyard"
- Use the toolbar button "Analyze Function with Zenyard"
- Use the menu: `Zenyard → Analyze Current Function`

### Copilot

Open the Copilot window:
- Menu: `Window → Zenyard Copilot`
- Or use the toolbar button

The Copilot window allows you to ask questions about the current function, selection, or binary.

## Logging

Logs are written to:
- `<project_dir>/<binary_name>.log` (per-project)
- Or `<ghidra_user_dir>/logs/zenyard/<project_name>.log`

Logs include:
- Analysis steps
- API calls
- Errors
- User actions

## Development

### OpenAPI Client Generation

The project uses OpenAPI Generator to create the Java client from the API specification. The `openapi.json` file must be present in the project root directory.

#### Obtaining openapi.json

**Option 1: Download from local cluster (recommended for development)**

If you have the Zenyard service running locally, you can download the latest OpenAPI spec:

```bash
# Download from default local cluster URL (http://localhost:32304/openapi.json)
./gradlew downloadOpenApiSpecFromCluster

# Or specify a custom URL
OPENAPI_JSON_URL=http://localhost:32304/openapi.json ./gradlew downloadOpenApiSpecFromCluster
```

**Option 2: Manual download**

Download the `openapi.json` file from your running Zenyard service:

```bash
# Using curl
curl http://localhost:32304/openapi.json -o openapi.json

# Or using wget
wget http://localhost:32304/openapi.json -O openapi.json
```

**Option 3: Copy from zenyard service**

If you have access to the zenyard service repository, you can copy the generated OpenAPI spec from there.

#### Generating the Java Client

Once `openapi.json` is in the project root, the Java client is automatically generated during the build:

```bash
# Generate OpenAPI client only
./gradlew openApiGenerate

# Or build the extension (which includes client generation)
./gradlew buildExtension
```

The generated client code will be in `build/generated/src/main/java/com/zenyard/ghidra/api/generated/`.

**Note:** The `downloadOpenApiSpecFromCluster` task is optional and not part of the default build flow. It's useful for keeping the client in sync with a running local development server.

### Building (Development)

```bash
./gradlew buildExtension
```

See [Building](#building) above for cross-platform build options.

### Project Structure

```
zenyard-ghidra/
├── src/main/java/com/zenyard/ghidra/
│   ├── ZenyardGhidraPlugin.java      # Main plugin entry point
│   ├── ZenyardService.java            # Service registry
│   ├── api/                            # API client
│   ├── illum/                          # Illuminator features
│   ├── copilot/                        # Copilot module
│   ├── status/                         # Status bar integration
│   ├── config/                         # Configuration UI
│   ├── storage/                        # Data storage
│   ├── initialization/                 # Initial analysis flow
│   └── util/                           # Utilities
├── resources/
│   └── icons/                          # Plugin icons
└── build.gradle                        # Build configuration
```

## License

[To be determined]

## Support

For issues and questions, please contact [support information].

