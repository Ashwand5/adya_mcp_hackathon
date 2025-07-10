import os
import re
import shlex
import subprocess
import platform
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("cli-mcp-server")


class CommandError(Exception):
    """Base exception for command-related errors"""

    pass


class CommandSecurityError(CommandError):
    """Security violation errors"""

    pass


class CommandExecutionError(CommandError):
    """Command execution errors"""

    pass


class CommandTimeoutError(CommandError):
    """Command timeout errors"""

    pass


@dataclass
class SecurityConfig:
    """
    Security configuration for command execution
    """

    allowed_commands: set[str]
    allowed_flags: set[str]
    max_command_length: int
    command_timeout: int
    allow_all_commands: bool = False
    allow_all_flags: bool = False
    allow_shell_operators: bool = False


class CommandExecutor:
    def __init__(self, allowed_dir: str, security_config: SecurityConfig):
        if not allowed_dir or not os.path.exists(allowed_dir):
            raise ValueError("Valid ALLOWED_DIR is required")
        self.allowed_dir = os.path.abspath(os.path.realpath(allowed_dir))
        self.security_config = security_config

        # Detect if we're on Windows and should use WSL
        self.use_wsl = platform.system() == "Windows"
        self.wsl_distro = os.getenv("WSL_DISTRO", "FedoraLinux-42")

        print(f"DEBUG: Platform detected: {platform.system()}", flush=True)
        print(f"DEBUG: Using WSL: {self.use_wsl}", flush=True)
        if self.use_wsl:
            print(f"DEBUG: WSL Distro: {self.wsl_distro}", flush=True)

    def _wrap_command_for_wsl(self, command: str, args: List[str]) -> tuple[str, List[str]]:
        """
        Wraps a command to run through WSL if on Windows.

        Args:
            command (str): The base command
            args (List[str]): Command arguments

        Returns:
            tuple[str, List[str]]: WSL-wrapped command and args
        """
        if not self.use_wsl:
            return command, args

        # Convert Windows paths to WSL paths for arguments
        converted_args = []
        for arg in args:
            if os.path.isabs(arg) and len(arg) > 2 and arg[1] == ':':
                # Convert Windows path to WSL path
                # Example: D:\path\to\dir -> /mnt/d/path/to/dir
                drive_letter = arg[0].lower()
                path_part = arg[3:].replace('\\', '/')  # Remove drive letter and colon, convert slashes
                wsl_path = f"/mnt/{drive_letter}/{path_part}"
                converted_args.append(wsl_path)
            else:
                converted_args.append(arg)

        # Build WSL command - use a simpler approach
        # Instead of separate args, build a single command string
        if converted_args:
            full_command = f"{command} {' '.join(converted_args)}"
        else:
            full_command = command

        wsl_command = "wsl"
        wsl_args = ["-d", self.wsl_distro, "bash", "-c", full_command]

        print(f"DEBUG: WSL command: {wsl_command} {' '.join(wsl_args)}", flush=True)
        return wsl_command, wsl_args

    def _normalize_path(self, path: str) -> str:
        """
        Normalizes a path and ensures it's within allowed directory.
        """
        try:
            if os.path.isabs(path):
                # If absolute path, check directly
                real_path = os.path.abspath(os.path.realpath(path))
            else:
                # If relative path, combine with allowed_dir first
                real_path = os.path.abspath(
                    os.path.realpath(os.path.join(self.allowed_dir, path))
                )

            if not self._is_path_safe(real_path):
                raise CommandSecurityError(
                    f"Path '{path}' is outside of allowed directory: {self.allowed_dir}"
                )

            return real_path
        except CommandSecurityError:
            raise
        except Exception as e:
            raise CommandSecurityError(f"Invalid path '{path}': {str(e)}")

    def validate_command(self, command_string: str) -> tuple[str, List[str]]:
        """
        Validates and parses a command string for security and formatting.

        Checks if the command string contains shell operators. If it does, splits the command
        by operators and validates each part individually. If all parts are valid, returns
        the original command string to be executed with shell=True.

        For commands without shell operators, splits into command and arguments and validates
        each part according to security rules.

        Args:
            command_string (str): The command string to validate and parse.

        Returns:
            tuple[str, List[str]]: A tuple containing:
                - For regular commands: The command name (str) and list of arguments (List[str])
                - For commands with shell operators: The full command string and empty args list

        Raises:
            CommandSecurityError: If any part of the command fails security validation.
        """

        # Define shell operators
        shell_operators = ["&&", "||", "|", ">", ">>", "<", "<<", ";"]

        # Check if command contains shell operators
        contains_shell_operator = any(
            operator in command_string for operator in shell_operators
        )

        if contains_shell_operator:
            # Check if shell operators are allowed
            if not self.security_config.allow_shell_operators:
                # If shell operators are not allowed, raise an error
                for operator in shell_operators:
                    if operator in command_string:
                        raise CommandSecurityError(
                            f"Shell operator '{operator}' is not supported. Set ALLOW_SHELL_OPERATORS=true to enable."
                        )

            # Split the command by shell operators and validate each part
            return self._validate_command_with_operators(
                command_string, shell_operators
            )

        # Process single command without shell operators
        return self._validate_single_command(command_string)

    def _is_url_path(self, path: str) -> bool:
        """
        Checks if a given path is a URL of type http or https.

        Args:
            path (str): The path to check.

        Returns:
            bool: True if the path is a URL, False otherwise.
        """
        url_pattern = re.compile(r"^https?://")
        return bool(url_pattern.match(path))

    def _is_path_safe(self, path: str) -> bool:
        """
        Checks if a given path is safe to access within allowed directory boundaries.

        Validates that the absolute resolved path is within the allowed directory
        to prevent directory traversal attacks.

        Args:
            path (str): The path to validate.

        Returns:
            bool: True if path is within allowed directory, False otherwise.
                Returns False if path resolution fails for any reason.

        Private method intended for internal use only.
        """
        try:
            # Resolve any symlinks and get absolute path
            real_path = os.path.abspath(os.path.realpath(path))
            allowed_dir_real = os.path.abspath(os.path.realpath(self.allowed_dir))

            # Check if the path starts with allowed_dir
            return real_path.startswith(allowed_dir_real)
        except Exception:
            return False

    def _is_combined_flag(self, flag: str) -> bool:
        """
        Check if a flag is a combined flag (e.g., -la, -rf).

        Args:
            flag (str): The flag to check.

        Returns:
            bool: True if it's a combined flag, False otherwise.
        """
        # Combined flags start with single dash and have multiple characters (excluding long flags with --)
        return flag.startswith("-") and not flag.startswith("--") and len(flag) > 2

    def _expand_combined_flag(self, combined_flag: str) -> List[str]:
        """
        Expand a combined flag into individual flags.

        Args:
            combined_flag (str): The combined flag (e.g., -la).

        Returns:
            List[str]: List of individual flags (e.g., ['-l', '-a']).
        """
        if not self._is_combined_flag(combined_flag):
            return [combined_flag]

        # Remove the leading dash and split into individual characters
        flag_chars = combined_flag[1:]
        return [f"-{char}" for char in flag_chars]

    def _validate_single_command(self, command_string: str) -> tuple[str, List[str]]:
        """
        Validates a single command without shell operators.

        Args:
            command_string (str): The command string to validate.

        Returns:
            tuple[str, List[str]]: A tuple containing the command and validated arguments.

        Raises:
            CommandSecurityError: If the command fails validation.
        """
        print(f"DEBUG: _validate_single_command called with: '{command_string}'", flush=True)
        try:
            parts = shlex.split(command_string)
            if not parts:
                raise CommandSecurityError("Empty command")

            command, args = parts[0], parts[1:]
            print(f"DEBUG: Command parsed as: command='{command}', args={args}", flush=True)

            # Validate command if not in allow-all mode
            if (
                not self.security_config.allow_all_commands
                and command not in self.security_config.allowed_commands
            ):
                print(f"DEBUG: Command '{command}' not in allowed commands: {self.security_config.allowed_commands}", flush=True)
                raise CommandSecurityError(f"Command '{command}' is not allowed")

            # Process and validate arguments
            validated_args = []
            for arg in args:
                if arg.startswith("-"):
                    # Handle combined flags like -la by expanding them
                    if self._is_combined_flag(arg):
                        expanded_flags = self._expand_combined_flag(arg)
                        for flag in expanded_flags:
                            if (
                                not self.security_config.allow_all_flags
                                and flag not in self.security_config.allowed_flags
                            ):
                                raise CommandSecurityError(f"Flag '{flag}' is not allowed")
                        validated_args.extend(expanded_flags)
                    else:
                        if (
                            not self.security_config.allow_all_flags
                            and arg not in self.security_config.allowed_flags
                        ):
                            raise CommandSecurityError(f"Flag '{arg}' is not allowed")
                        validated_args.append(arg)
                    continue

                # For any path-like argument, validate it
                if "/" in arg or "\\" in arg or os.path.isabs(arg) or arg == ".":
                    if self._is_url_path(arg):
                        # If it's a URL, we don't need to normalize it
                        validated_args.append(arg)
                        continue

                    normalized_path = self._normalize_path(arg)
                    validated_args.append(normalized_path)
                else:
                    # For non-path arguments, add them as-is
                    validated_args.append(arg)

            return command, validated_args

        except ValueError as e:
            raise CommandSecurityError(f"Invalid command format: {str(e)}")

    def _validate_command_with_operators(
        self, command_string: str, shell_operators: List[str]
    ) -> tuple[str, List[str]]:
        """
        Validates a command string that contains shell operators.

        Splits the command string by shell operators and validates each part individually.
        If all parts are valid, returns the original command to be executed with shell=True.

        Args:
            command_string (str): The command string containing shell operators.
            shell_operators (List[str]): List of shell operators to split by.

        Returns:
            tuple[str, List[str]]: A tuple containing the command and empty args list
                                  (since the command will be executed with shell=True)

        Raises:
            CommandSecurityError: If any part of the command fails validation.
        """
        # Create a regex pattern to split by any of the shell operators
        # We need to escape special regex characters in the operators
        escaped_operators = [re.escape(op) for op in shell_operators]
        pattern = "|".join(escaped_operators)

        # Split the command string by shell operators, keeping the operators
        parts = re.split(f"({pattern})", command_string)

        # Filter out empty parts and whitespace-only parts
        parts = [part.strip() for part in parts if part.strip()]

        # Group commands and operators
        commands = []
        i = 0
        while i < len(parts):
            if i + 1 < len(parts) and parts[i + 1] in shell_operators:
                # If next part is an operator, current part is a command
                if parts[i]:  # Skip empty commands
                    commands.append(parts[i])
                i += 2  # Skip the operator
            else:
                # If no operator follows, this is the last command
                if (
                    parts[i] and parts[i] not in shell_operators
                ):  # Skip if it's an operator
                    commands.append(parts[i])
                i += 1

        # Validate each command individually
        for cmd in commands:
            try:
                # Use the extracted validation method for each command
                self._validate_single_command(cmd)
            except CommandSecurityError as e:
                raise CommandSecurityError(f"Invalid command part '{cmd}': {str(e)}")
            except ValueError as e:
                raise CommandSecurityError(
                    f"Invalid command format in '{cmd}': {str(e)}"
                )

        # If we get here, all commands passed validation
        # Return the original command string to be executed with shell=True
        return command_string, []

    def execute(self, command_string: str) -> subprocess.CompletedProcess:
        """
        Executes a command string in a secure, controlled environment.

        Runs the command after validating it against security constraints including length limits
        and shell operator restrictions. Executes with controlled parameters for safety.

        Args:
            command_string (str): The command string to execute.

        Returns:
            subprocess.CompletedProcess: The result of the command execution containing
                stdout, stderr, and return code.

        Raises:
            CommandSecurityError: If the command:
                - Exceeds maximum length
                - Fails security validation
                - Fails during execution

        Notes:
            - Uses shell=True for commands with shell operators, shell=False otherwise
            - Uses timeout and working directory constraints
            - Captures both stdout and stderr
        """
        print(f"DEBUG: execute() called with command_string: '{command_string}'", flush=True)
        print(f"DEBUG: WSL mode enabled: {self.use_wsl}", flush=True)

        if len(command_string) > self.security_config.max_command_length:
            raise CommandSecurityError(
                f"Command exceeds maximum length of {self.security_config.max_command_length}"
            )

        try:
            command, args = self.validate_command(command_string)
            print(f"DEBUG: After validation - command: '{command}', args: {args}", flush=True)

            # Check if this is a command with shell operators
            shell_operators = ["&&", "||", "|", ">", ">>", "<", "<<", ";"]
            use_shell = any(operator in command_string for operator in shell_operators)
            print(f"DEBUG: use_shell: {use_shell}", flush=True)

            # Double-check that shell operators are allowed if they are present
            if use_shell and not self.security_config.allow_shell_operators:
                for operator in shell_operators:
                    if operator in command_string:
                        raise CommandSecurityError(
                            f"Shell operator '{operator}' is not supported. Set ALLOW_SHELL_OPERATORS=true to enable."
                        )

            if use_shell:
                # For commands with shell operators, execute with shell=True
                if self.use_wsl:
                    # For WSL with shell operators, wrap the entire command
                    wsl_command = f"wsl -d {self.wsl_distro} bash -c \"{command}\""
                    print(f"DEBUG: WSL shell command: {wsl_command}", flush=True)
                    return subprocess.run(
                        wsl_command,
                        shell=True,
                        text=True,
                        capture_output=True,
                        timeout=self.security_config.command_timeout,
                        cwd=self.allowed_dir,
                    )
                else:
                    return subprocess.run(
                        command,  # command is the full command string in this case
                        shell=True,
                        text=True,
                        capture_output=True,
                        timeout=self.security_config.command_timeout,
                        cwd=self.allowed_dir,
                    )
            else:
                # For regular commands, execute with shell=False
                if self.use_wsl:
                    print(f"DEBUG: Using WSL for command execution", flush=True)
                    wrapped_command, wrapped_args = self._wrap_command_for_wsl(command, args)
                    print(f"DEBUG: Final command to execute: {wrapped_command} {wrapped_args}", flush=True)
                    return subprocess.run(
                        [wrapped_command] + wrapped_args,
                        shell=False,
                        text=True,
                        capture_output=True,
                        timeout=self.security_config.command_timeout,
                        cwd=self.allowed_dir,
                    )
                else:
                    print(f"DEBUG: Using direct command execution (no WSL)", flush=True)
                    return subprocess.run(
                        [command] + args,
                        shell=False,
                        text=True,
                        capture_output=True,
                        timeout=self.security_config.command_timeout,
                        cwd=self.allowed_dir,
                    )
        except subprocess.TimeoutExpired:
            raise CommandTimeoutError(
                f"Command timed out after {self.security_config.command_timeout} seconds"
            )
        except CommandError:
            raise
        except Exception as e:
            raise CommandExecutionError(f"Command execution failed: {str(e)}")


# Load security configuration from environment
def load_security_config() -> SecurityConfig:
    """
    Loads security configuration from environment variables with default fallbacks.

    Creates a SecurityConfig instance using environment variables to configure allowed
    commands, flags, patterns, and execution constraints. Uses predefined defaults if
    environment variables are not set.

    Returns:
        SecurityConfig: Configuration object containing:
            - allowed_commands: Set of permitted command names
            - allowed_flags: Set of permitted command flags/options
            - max_command_length: Maximum length of command string
            - command_timeout: Maximum execution time in seconds
            - allow_all_commands: Whether all commands are allowed
            - allow_all_flags: Whether all flags are allowed
            - allow_shell_operators: Whether shell operators (&&, ||, |, etc.) are allowed

    Environment Variables:
        ALLOWED_COMMANDS: Comma-separated list of allowed commands or 'all' (default: "ls,cat,pwd")
        ALLOWED_FLAGS: Comma-separated list of allowed flags or 'all' (default: "-l,-a,--help")
        MAX_COMMAND_LENGTH: Maximum command string length (default: 1024)
        COMMAND_TIMEOUT: Command timeout in seconds (default: 30)
        ALLOW_SHELL_OPERATORS: Whether to allow shell operators like &&, ||, |, >, etc. (default: false)
                              Set to "true" or "1" to enable, any other value to disable.
    """
    allowed_commands = os.getenv("ALLOWED_COMMANDS", "ls,cat,pwd")
    allowed_flags = os.getenv("ALLOWED_FLAGS", "-l,-a,--help")
    allow_shell_operators_env = os.getenv("ALLOW_SHELL_OPERATORS", "false")

    allow_all_commands = allowed_commands.lower() == "all"
    allow_all_flags = allowed_flags.lower() == "all"
    allow_shell_operators = allow_shell_operators_env.lower() in ("true", "1")

    return SecurityConfig(
        allowed_commands=(
            set() if allow_all_commands else set(allowed_commands.split(","))
        ),
        allowed_flags=set() if allow_all_flags else set(allowed_flags.split(",")),
        max_command_length=int(os.getenv("MAX_COMMAND_LENGTH", "1024")),
        command_timeout=int(os.getenv("COMMAND_TIMEOUT", "30")),
        allow_all_commands=allow_all_commands,
        allow_all_flags=allow_all_flags,
        allow_shell_operators=allow_shell_operators,
    )


executor = CommandExecutor(
    allowed_dir=os.getenv("ALLOWED_DIR", ""), security_config=load_security_config()
)


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    commands_desc = (
        "all commands"
        if executor.security_config.allow_all_commands
        else ", ".join(executor.security_config.allowed_commands)
    )
    flags_desc = (
        "all flags"
        if executor.security_config.allow_all_flags
        else ", ".join(executor.security_config.allowed_flags)
    )

    return [
        types.Tool(
            name="run_command",
            description=(
                f"Allows command (CLI) execution in the directory: {executor.allowed_dir}\n\n"
                f"Available commands: {commands_desc}\n"
                f"Available flags: {flags_desc}\n\n"
                f"Shell operators (&&, ||, |, >, >>, <, <<, ;) are {'supported' if executor.security_config.allow_shell_operators else 'not supported'}. Set ALLOW_SHELL_OPERATORS=true to enable."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Single command to execute (example: 'ls -l' or 'cat file.txt')",
                    }
                },
                "required": ["command"],
            },
        ),
        types.Tool(
            name="show_security_rules",
            description=(
                "Show what commands and operations are allowed in this environment.\n"
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="list_directory",
            description=(
                "List contents of a directory with detailed information including file sizes, permissions, and timestamps."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path to list (relative to allowed directory). Use '.' for current directory.",
                    },
                    "show_hidden": {
                        "type": "boolean",
                        "description": "Whether to show hidden files (files starting with .)",
                        "default": False
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Whether to list subdirectories recursively",
                        "default": False
                    }
                },
                "required": ["path"],
            },
        ),
        types.Tool(
            name="read_file",
            description=(
                "Read and display the contents of a text file with optional line numbering and range selection."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to read (relative to allowed directory)",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Starting line number (1-based). If not provided, reads from beginning.",
                        "minimum": 1
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Ending line number (1-based). If not provided, reads to end.",
                        "minimum": 1
                    },
                    "show_line_numbers": {
                        "type": "boolean",
                        "description": "Whether to show line numbers",
                        "default": True
                    }
                },
                "required": ["file_path"],
            },
        ),
        types.Tool(
            name="search_files",
            description=(
                "Search for files by name pattern or search for text content within files."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Search pattern (filename pattern or text to search for)",
                    },
                    "search_type": {
                        "type": "string",
                        "enum": ["filename", "content"],
                        "description": "Type of search: 'filename' to search by filename pattern, 'content' to search within file contents",
                        "default": "filename"
                    },
                    "directory": {
                        "type": "string",
                        "description": "Directory to search in (relative to allowed directory). Use '.' for current directory.",
                        "default": "."
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Whether to search recursively in subdirectories",
                        "default": True
                    }
                },
                "required": ["pattern"],
            },
        ),
        types.Tool(
            name="get_file_info",
            description=(
                "Get detailed information about a file or directory including size, permissions, timestamps, and type."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file or directory (relative to allowed directory)",
                    }
                },
                "required": ["path"],
            },
        ),
        types.Tool(
            name="create_directory",
            description=(
                "Create a new directory with optional parent directory creation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "directory_path": {
                        "type": "string",
                        "description": "Path of the directory to create (relative to allowed directory)",
                    },
                    "create_parents": {
                        "type": "boolean",
                        "description": "Whether to create parent directories if they don't exist",
                        "default": True
                    }
                },
                "required": ["directory_path"],
            },
        ),
        types.Tool(
            name="write_file",
            description=(
                "Write content to a file. Can create new files or overwrite existing ones."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to write (relative to allowed directory)",
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write to the file",
                    },
                    "append": {
                        "type": "boolean",
                        "description": "Whether to append to the file instead of overwriting",
                        "default": False
                    }
                },
                "required": ["file_path", "content"],
            },
        ),
        types.Tool(
            name="system_info",
            description=(
                "Get system information including OS details, disk usage, memory usage, and current working directory."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "info_type": {
                        "type": "string",
                        "enum": ["all", "os", "disk", "memory", "network"],
                        "description": "Type of system information to retrieve",
                        "default": "all"
                    }
                },
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: Optional[Dict[str, Any]]
) -> List[types.TextContent]:
    if name == "run_command":
        if not arguments or "command" not in arguments:
            return [
                types.TextContent(type="text", text="No command provided", error=True)
            ]

        try:
            result = executor.execute(arguments["command"])

            response = []
            if result.stdout:
                response.append(types.TextContent(type="text", text=result.stdout))
            if result.stderr:
                response.append(
                    types.TextContent(type="text", text=result.stderr, error=True)
                )

            response.append(
                types.TextContent(
                    type="text",
                    text=f"\nCommand completed with return code: {result.returncode}",
                )
            )

            return response

        except CommandSecurityError as e:
            return [
                types.TextContent(
                    type="text", text=f"Security violation: {str(e)}", error=True
                )
            ]
        except subprocess.TimeoutExpired:
            return [
                types.TextContent(
                    type="text",
                    text=f"Command timed out after {executor.security_config.command_timeout} seconds",
                    error=True,
                )
            ]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {str(e)}", error=True)]

    elif name == "show_security_rules":
        commands_desc = (
            "All commands allowed"
            if executor.security_config.allow_all_commands
            else ", ".join(sorted(executor.security_config.allowed_commands))
        )
        flags_desc = (
            "All flags allowed"
            if executor.security_config.allow_all_flags
            else ", ".join(sorted(executor.security_config.allowed_flags))
        )

        security_info = (
            "Security Configuration:\n"
            f"==================\n"
            f"Working Directory: {executor.allowed_dir}\n"
            f"\nAllowed Commands:\n"
            f"----------------\n"
            f"{commands_desc}\n"
            f"\nAllowed Flags:\n"
            f"-------------\n"
            f"{flags_desc}\n"
            f"\nSecurity Limits:\n"
            f"---------------\n"
            f"Max Command Length: {executor.security_config.max_command_length} characters\n"
            f"Command Timeout: {executor.security_config.command_timeout} seconds\n"
        )
        return [types.TextContent(type="text", text=security_info)]

    elif name == "list_directory":
        path = arguments.get("path", ".") if arguments else "."
        show_hidden = arguments.get("show_hidden", False) if arguments else False
        recursive = arguments.get("recursive", False) if arguments else False

        try:
            # Build ls command
            cmd_parts = ["ls", "-l"]
            if show_hidden:
                cmd_parts.append("-a")
            if recursive:
                cmd_parts.append("-R")
            cmd_parts.append(path)

            result = executor.execute(" ".join(cmd_parts))

            response = []
            if result.stdout:
                # Check if directory is empty (only contains "total 0" line)
                stdout_lines = result.stdout.strip().split('\n')
                if len(stdout_lines) == 1 and stdout_lines[0].startswith("total 0"):
                    response.append(types.TextContent(type="text", text=f"Directory '{path}' is empty (no files or subdirectories found)."))
                else:
                    response.append(types.TextContent(type="text", text=f"Directory listing for '{path}':\n{result.stdout}"))
            else:
                response.append(types.TextContent(type="text", text=f"Directory '{path}' is empty or could not be read."))

            if result.stderr:
                response.append(types.TextContent(type="text", text=result.stderr, error=True))

            return response

        except Exception as e:
            return [types.TextContent(type="text", text=f"Error listing directory: {str(e)}", error=True)]

    elif name == "read_file":
        if not arguments or "file_path" not in arguments:
            return [types.TextContent(type="text", text="No file path provided", error=True)]

        file_path = arguments["file_path"]
        start_line = arguments.get("start_line")
        end_line = arguments.get("end_line")
        show_line_numbers = arguments.get("show_line_numbers", True)

        try:
            # Build command based on parameters
            if start_line or end_line:
                if start_line and end_line:
                    cmd = f"sed -n '{start_line},{end_line}p' {file_path}"
                elif start_line:
                    cmd = f"tail -n +{start_line} {file_path}"
                else:
                    cmd = f"head -n {end_line} {file_path}"
            else:
                cmd = f"cat {file_path}"

            if show_line_numbers and not (start_line or end_line):
                cmd = f"cat -n {file_path}"

            result = executor.execute(cmd)

            response = []
            if result.stdout:
                response.append(types.TextContent(type="text", text=f"Contents of '{file_path}':\n{result.stdout}"))
            if result.stderr:
                response.append(types.TextContent(type="text", text=result.stderr, error=True))

            return response

        except Exception as e:
            return [types.TextContent(type="text", text=f"Error reading file: {str(e)}", error=True)]

    elif name == "search_files":
        if not arguments or "pattern" not in arguments:
            return [types.TextContent(type="text", text="No search pattern provided", error=True)]

        pattern = arguments["pattern"]
        search_type = arguments.get("search_type", "filename")
        directory = arguments.get("directory", ".")
        recursive = arguments.get("recursive", True)

        try:
            if search_type == "filename":
                cmd_parts = ["find", directory]
                if not recursive:
                    cmd_parts.extend(["-maxdepth", "1"])
                cmd_parts.extend(["-name", f"*{pattern}*", "-type", "f"])
            else:  # content search
                cmd_parts = ["grep", "-r" if recursive else "", "-l", pattern, directory]
                cmd_parts = [part for part in cmd_parts if part]  # Remove empty strings

            result = executor.execute(" ".join(cmd_parts))

            response = []
            if result.stdout:
                response.append(types.TextContent(type="text", text=f"Search results for '{pattern}' ({search_type}):\n{result.stdout}"))
            else:
                response.append(types.TextContent(type="text", text=f"No results found for '{pattern}' ({search_type})"))
            if result.stderr:
                response.append(types.TextContent(type="text", text=result.stderr, error=True))

            return response

        except Exception as e:
            return [types.TextContent(type="text", text=f"Error searching: {str(e)}", error=True)]

    elif name == "get_file_info":
        if not arguments or "path" not in arguments:
            return [types.TextContent(type="text", text="No path provided", error=True)]

        path = arguments["path"]

        try:
            # Use stat command to get detailed file information
            result = executor.execute(f"stat {path}")

            response = []
            if result.stdout:
                response.append(types.TextContent(type="text", text=f"File information for '{path}':\n{result.stdout}"))
            if result.stderr:
                response.append(types.TextContent(type="text", text=result.stderr, error=True))

            return response

        except Exception as e:
            return [types.TextContent(type="text", text=f"Error getting file info: {str(e)}", error=True)]

    elif name == "create_directory":
        if not arguments or "directory_path" not in arguments:
            return [types.TextContent(type="text", text="No directory path provided", error=True)]

        directory_path = arguments["directory_path"]
        create_parents = arguments.get("create_parents", True)

        try:
            cmd = f"mkdir {'-p ' if create_parents else ''}{directory_path}"
            result = executor.execute(cmd)

            response = []
            if result.returncode == 0:
                response.append(types.TextContent(type="text", text=f"Successfully created directory: {directory_path}"))
            if result.stderr:
                response.append(types.TextContent(type="text", text=result.stderr, error=True))

            return response

        except Exception as e:
            return [types.TextContent(type="text", text=f"Error creating directory: {str(e)}", error=True)]

    elif name == "write_file":
        if not arguments or "file_path" not in arguments or "content" not in arguments:
            return [types.TextContent(type="text", text="File path and content are required", error=True)]

        file_path = arguments["file_path"]
        content = arguments["content"]
        append = arguments.get("append", False)

        # Debug logging
        print(f"DEBUG: write_file called with file_path='{file_path}', content length={len(content)}", flush=True)

        try:
            # Use Python's built-in file operations instead of shell redirection
            # to avoid shell operator restrictions
            import os

            print(f"DEBUG: Starting file write process for '{file_path}'", flush=True)

            # Manually validate the file path without using command validation
            if os.path.isabs(file_path):
                # If absolute path, check directly
                full_path = os.path.abspath(os.path.realpath(file_path))
                print(f"DEBUG: Absolute path resolved to '{full_path}'", flush=True)
            else:
                # If relative path, combine with allowed_dir first
                full_path = os.path.abspath(
                    os.path.realpath(os.path.join(executor.allowed_dir, file_path))
                )
                print(f"DEBUG: Relative path resolved to '{full_path}'", flush=True)

            # Check if the path is within allowed directory
            allowed_dir_real = os.path.abspath(os.path.realpath(executor.allowed_dir))
            print(f"DEBUG: Allowed directory is '{allowed_dir_real}'", flush=True)

            if not full_path.startswith(allowed_dir_real):
                print(f"DEBUG: Path validation failed - outside allowed directory", flush=True)
                return [types.TextContent(type="text", text=f"Path '{file_path}' is outside allowed directory", error=True)]

            print(f"DEBUG: Path validation passed, writing file", flush=True)

            # Write the file using Python
            mode = "a" if append else "w"
            with open(full_path, mode, encoding="utf-8") as f:
                f.write(content)

            action = "appended to" if append else "written to"
            print(f"DEBUG: File write successful", flush=True)
            return [types.TextContent(type="text", text=f"Content successfully {action} file: {file_path}")]

        except Exception as e:
            print(f"DEBUG: Exception in write_file: {str(e)}", flush=True)
            return [types.TextContent(type="text", text=f"Error writing file: {str(e)}", error=True)]

    elif name == "system_info":
        info_type = arguments.get("info_type", "all") if arguments else "all"

        try:
            info_parts = []

            if info_type in ["all", "os"]:
                os_result = executor.execute("uname -a")
                if os_result.stdout:
                    info_parts.append(f"OS Information:\n{os_result.stdout}")

            if info_type in ["all", "disk"]:
                disk_result = executor.execute("df -h")
                if disk_result.stdout:
                    info_parts.append(f"Disk Usage:\n{disk_result.stdout}")

            if info_type in ["all", "memory"]:
                mem_result = executor.execute("free -h")
                if mem_result.stdout:
                    info_parts.append(f"Memory Usage:\n{mem_result.stdout}")

            if info_type in ["all"]:
                pwd_result = executor.execute("pwd")
                if pwd_result.stdout:
                    info_parts.append(f"Current Directory:\n{pwd_result.stdout}")

            if info_parts:
                return [types.TextContent(type="text", text="\n\n".join(info_parts))]
            else:
                return [types.TextContent(type="text", text="No system information available")]

        except Exception as e:
            return [types.TextContent(type="text", text=f"Error getting system info: {str(e)}", error=True)]

    raise ValueError(f"Unknown tool: {name}")


async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="cli-mcp-server",
                server_version="0.2.1",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )
