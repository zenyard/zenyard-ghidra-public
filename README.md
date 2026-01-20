# DecompAI Ghidra Plugin

A Ghidra plugin that provides AI-powered reverse engineering assistance through the DecompAI service.

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
- External (remote) API interactions with DecompAI API server
- License configuration screen

## Requirements

- Ghidra 11.x (desktop)
- Java 11 or later
- Network access to DecompAI API server

## Installation

- Complete this section

## Configuration

The plugin requires:
- **API Key**: Your DecompAI API key
- **Server URL**: The base URL of the DecompAI API server (default: `https://api.decompai.com`)

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
- Right-click on a function in the listing → "Analyze with DecompAI"
- Use the toolbar button "Analyze Function with DecompAI"
- Use the menu: `DecompAI → Analyze Current Function`

### Copilot

Open the Copilot window:
- Menu: `Window → DecompAI Copilot`
- Or use the toolbar button

The Copilot window allows you to ask questions about the current function, selection, or binary.

## Logging

Logs are written to:
- `<project_dir>/<binary_name>.log` (per-project)
- Or `<ghidra_user_dir>/logs/decompai/<project_name>.log`

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

If you have the DecompAI service running locally, you can download the latest OpenAPI spec:

```bash
# Download from default local cluster URL (http://localhost:32304/openapi.json)
./gradlew downloadOpenApiSpecFromCluster

# Or specify a custom URL
OPENAPI_JSON_URL=http://localhost:32304/openapi.json ./gradlew downloadOpenApiSpecFromCluster
```

**Option 2: Manual download**

Download the `openapi.json` file from your running DecompAI service:

```bash
# Using curl
curl http://localhost:32304/openapi.json -o openapi.json

# Or using wget
wget http://localhost:32304/openapi.json -O openapi.json
```

**Option 3: Copy from decompai service**

If you have access to the decompai service repository, you can copy the generated OpenAPI spec from there.

#### Generating the Java Client

Once `openapi.json` is in the project root, the Java client is automatically generated during the build:

```bash
# Generate OpenAPI client only
./gradlew openApiGenerate

# Or build the extension (which includes client generation)
./gradlew buildExtension
```

The generated client code will be in `build/generated/src/main/java/com/zenyard/decompai/ghidra/api/generated/`.

**Note:** The `downloadOpenApiSpecFromCluster` task is optional and not part of the default build flow. It's useful for keeping the client in sync with a running local development server.

### Building

```bash
./gradlew buildExtension
```

### Project Structure

```
decompai-ghidra/
├── src/main/java/com/zenyard/decompai/ghidra/
│   ├── DecompaiGhidraPlugin.java      # Main plugin entry point
│   ├── DecompaiServices.java          # Service registry
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

