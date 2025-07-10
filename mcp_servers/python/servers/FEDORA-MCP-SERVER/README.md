# FEDORA-MCP-SERVER

---

A secure Model Context Protocol (MCP) server implementation for executing controlled Unix/Linux command-line operations with
comprehensive security features and WSL (Windows Subsystem for Linux) integration.

---

# Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Configuration](#configuration)
4. [Available Tools](#available-tools)
    - [run_command](#run_command)
    - [show_security_rules](#show_security_rules)
5. [Usage with Claude Desktop](#usage-with-claude-desktop)
    - [Development/Unpublished Servers Configuration](#developmentunpublished-servers-configuration)
    - [Published Servers Configuration](#published-servers-configuration)
6. [Security Features](#security-features)
7. [Error Handling](#error-handling)
8. [Development](#development)
    - [Prerequisites](#prerequisites)
    - [Building and Publishing](#building-and-publishing)
    - [Debugging](#debugging)
9. [License](#license)

---

## Overview

This MCP server enables secure command-line execution with robust security measures including command whitelisting, path
validation, and execution controls. Perfect for providing controlled CLI access to LLM applications while maintaining security.

## Features

- 🔒 **Secure Command Execution**: Strict validation and whitelisting
- 🐧 **WSL Integration**: Seamless Linux command execution on Windows
- ⚙️ **Configurable Whitelisting**: Command and flag whitelisting with 'all' option
- 🛡️ **Path Traversal Prevention**: Secure directory restrictions
- 🚫 **Shell Injection Protection**: Shell operator validation
- ⏱️ **Execution Controls**: Timeouts and length limits
- 🔄 **Cross-Platform**: Works on Windows with WSL and native Linux
- 📁 **File Operations**: Safe file and directory management
- 📝 Detailed error reporting
- 🔄 Async operation support
- 🎯 Working directory restriction and validation

## Configuration

Configure the server using environment variables:

| Variable             | Description                                          | Default            |
|---------------------|------------------------------------------------------|-------------------|
| `ALLOWED_DIR`       | Base directory for command execution (Required)      | None (Required)   |
| `ALLOWED_COMMANDS`  | Comma-separated list of allowed commands or 'all'    | `ls,cat,pwd`      |
| `ALLOWED_FLAGS`     | Comma-separated list of allowed flags or 'all'       | `-l,-a,--help`    |
| `MAX_COMMAND_LENGTH`| Maximum command string length                        | `1024`            |
| `COMMAND_TIMEOUT`   | Command execution timeout (seconds)                  | `30`              |
| `ALLOW_SHELL_OPERATORS` | Allow shell operators (&&, \|\|, \|, >, etc.)    | `false`           |

Note: Setting `ALLOWED_COMMANDS` or `ALLOWED_FLAGS` to 'all' will allow any command or flag respectively.

## Installation

To install CLI MCP Server for Claude Desktop automatically via [Smithery](https://smithery.ai/protocol/cli-mcp-server):

```bash
npx @smithery/cli install cli-mcp-server --client claude
```

## Available Tools

### run_command

Executes whitelisted CLI commands within allowed directories.

**Input Schema:**
```json
{
  "command": {
    "type": "string",
    "description": "Single command to execute (e.g., 'ls -l' or 'cat file.txt')"
  }
}
```

**Security Notes:**
- Shell operators (&&, |, >, >>) are not supported by default, but can be enabled with `ALLOW_SHELL_OPERATORS=true`
- Commands must be whitelisted unless ALLOWED_COMMANDS='all'
- Flags must be whitelisted unless ALLOWED_FLAGS='all'
- All paths are validated to be within ALLOWED_DIR

### show_security_rules

Displays current security configuration and restrictions, including:
- Working directory
- Allowed commands
- Allowed flags
- Security limits (max command length and timeout)

## Usage with Claude Desktop

Add to your `~/Library/Application\ Support/Claude/claude_desktop_config.json`:

> Development/Unpublished Servers Configuration

```json
{
  "mcpServers": {
    "cli-mcp-server": {
      "command": "uv",
      "args": [
        "--directory",
        "<path/to/the/repo>/cli-mcp-server",
        "run",
        "cli-mcp-server"
      ],
      "env": {
        "ALLOWED_DIR": "</your/desired/dir>",
        "ALLOWED_COMMANDS": "ls,cat,pwd,echo",
        "ALLOWED_FLAGS": "-l,-a,--help,--version",
        "MAX_COMMAND_LENGTH": "1024",
        "COMMAND_TIMEOUT": "30",
        "ALLOW_SHELL_OPERATORS": "false"
      }
    }
  }
}
```

> Published Servers Configuration

```json
{
  "mcpServers": {
    "cli-mcp-server": {
      "command": "uvx",
      "args": [
        "cli-mcp-server"
      ],
      "env": {
        "ALLOWED_DIR": "</your/desired/dir>",
        "ALLOWED_COMMANDS": "ls,cat,pwd,echo",
        "ALLOWED_FLAGS": "-l,-a,--help,--version",
        "MAX_COMMAND_LENGTH": "1024",
        "COMMAND_TIMEOUT": "30",
        "ALLOW_SHELL_OPERATORS": "false"
      }
    }
  }
}
```
> In case it's not working or showing in the UI, clear your cache via `uv clean`.

## Security Features

- ✅ Command whitelist enforcement with 'all' option
- ✅ Flag validation with 'all' option
- ✅ Path traversal prevention and normalization
- ✅ Shell operator blocking (with opt-in support via `ALLOW_SHELL_OPERATORS=true`)
- ✅ Command length limits
- ✅ Execution timeouts
- ✅ Working directory restrictions
- ✅ Symlink resolution and validation

## Error Handling

The server provides detailed error messages for:

- Security violations (CommandSecurityError)
- Command timeouts (CommandTimeoutError)
- Invalid command formats
- Path security violations
- Execution failures (CommandExecutionError)
- General command errors (CommandError)

## Development

### Prerequisites

- Python 3.10+
- MCP protocol library

### Building and Publishing

To prepare the package for distribution:

1. Sync dependencies and update lockfile:
    ```bash
    uv sync
    ```

2. Build package distributions:
    ```bash
    uv build
    ```

   > This will create source and wheel distributions in the `dist/` directory.

3. Publish to PyPI:
   ```bash
   uv publish --token {{YOUR_PYPI_API_TOKEN}}
   ```

### Debugging

Since MCP servers run over stdio, debugging can be challenging. For the best debugging
experience, we strongly recommend using the [MCP Inspector](https://github.com/modelcontextprotocol/inspector).

You can launch the MCP Inspector via [`npm`](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) with
this command:

```bash
npx @modelcontextprotocol/inspector uv --directory {{your source code local directory}}/cli-mcp-server run cli-mcp-server
```

Upon launching, the Inspector will display a URL that you can access in your browser to begin debugging.

## 📚 Demo Videos & Documentation

### Demo Videos
- **Fedora MCP Testing Demo**: [Watch Video](https://drive.google.com/file/d/1NY8UmxiFUwPWYSJhvXhD56dYRLAA-CGr/view?usp=sharing)

### Comprehensive Documentation
For detailed documentation, please refer to:
- **📋 Server Features**: [FEDORA-MCP-SERVER Documentation](../../../mcp_servers_documentation/FEDORA-MCP-SERVER/server_features.md)
- **🔐 WSL Setup Guide**: [Setup Guide](../../../mcp_servers_documentation/FEDORA-MCP-SERVER/credentials.md)
- **🎥 Demo Videos**: [Video Examples](../../../mcp_servers_documentation/FEDORA-MCP-SERVER/demo_videos.md)

### WSL Integration
This server includes comprehensive WSL integration for Windows users:
- **Automatic Platform Detection**: Detects Windows and enables WSL mode
- **Command Wrapping**: Wraps commands with `wsl -d FedoraLinux-42`
- **Path Translation**: Converts Windows paths to WSL mount points
- **Cross-Platform Compatibility**: Works seamlessly on Windows with WSL

---
