#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Aaron Conole

"""
Read-only tool calling support for DPDK AI review scripts.

Provides secure, sandboxed tools for AI to gather additional context:
- git log: View commit history
- git show: View specific commits
- grep: Search file contents
- awk/sed: Parse and extract text (read-only)
- file_read: Read file contents

All tools validate paths to prevent escaping the git repository.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Any, NoReturn


class ToolError(Exception):
    """Raised when a tool execution fails."""
    pass


class SecurityError(Exception):
    """Raised when a security constraint is violated."""
    pass


def get_git_root() -> Path:
    """Get the root directory of the git repository.

    Returns:
        Path to the git repository root

    Raises:
        ToolError: If not in a git repository
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise ToolError(f"Not in a git repository: {e}") from e


def validate_path(path_str: str, git_root: Path) -> Path:
    """Validate that a path is within the git repository.

    Uses Path.is_relative_to() to prevent directory traversal attacks.

    Args:
        path_str: Path string to validate
        git_root: Root of the git repository

    Returns:
        Resolved absolute Path object

    Raises:
        SecurityError: If path escapes the git repository
    """
    try:
        # Convert to absolute path and resolve symlinks
        if Path(path_str).is_absolute():
            resolved = Path(path_str).resolve()
        else:
            resolved = (git_root / path_str).resolve()

        # Check if path is within git root
        if not resolved.is_relative_to(git_root):
            raise SecurityError(
                f"Path '{path_str}' escapes git repository root '{git_root}'"
            )

        return resolved

    except (ValueError, OSError, RuntimeError) as e:
        raise SecurityError(f"Invalid path '{path_str}': {e}") from e


def validate_git_ref(ref: str) -> None:
    """Validate a git reference (commit hash, branch, tag).

    Args:
        ref: Git reference to validate

    Raises:
        SecurityError: If reference contains suspicious characters
    """
    # Allow alphanumeric, -, _, /, ^, ~, @ (normal git ref characters)
    # Disallow command injection characters: ; | & $ ( ) ` < > etc.
    if not re.match(r'^[a-zA-Z0-9._/^~@-]+$', ref):
        raise SecurityError(f"Invalid git reference: {ref}")


def tool_git_log(args: dict[str, Any], git_root: Path) -> str:
    """Execute git log with controlled arguments.

    Args:
        args: Dictionary with optional keys:
            - max_count: Maximum number of commits (default: 20, max: 100)
            - since: Date/time since (e.g., "2 weeks ago")
            - until: Date/time until
            - path: File path to filter by
            - grep: Commit message grep pattern
            - author: Author name/email filter
            - oneline: Use oneline format (default: False)

    Returns:
        Git log output as string

    Raises:
        ToolError: If git command fails
        SecurityError: If validation fails
    """
    cmd = ["git", "log"]

    # Validate and add max_count
    max_count = args.get("max_count", 20)
    if not isinstance(max_count, int) or max_count < 1 or max_count > 100:
        raise ToolError("max_count must be an integer between 1 and 100")
    cmd.extend([f"-{max_count}"])

    # Add optional filters
    if args.get("oneline"):
        cmd.append("--oneline")
    else:
        cmd.append("--format=%H%n%an <%ae>%n%ad%n%s%n%b%n---")

    if "since" in args:
        cmd.extend(["--since", args["since"]])

    if "until" in args:
        cmd.extend(["--until", args["until"]])

    if "author" in args:
        cmd.extend(["--author", args["author"]])

    if "grep" in args:
        cmd.extend(["--grep", args["grep"]])

    # Validate and add path filter
    if "path" in args:
        path = validate_path(args["path"], git_root)
        cmd.extend(["--", str(path)])

    try:
        result = subprocess.run(
            cmd,
            cwd=git_root,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise ToolError("git log timed out after 30 seconds")
    except subprocess.CalledProcessError as e:
        raise ToolError(f"git log failed: {e.stderr}")


def tool_git_show(args: dict[str, Any], git_root: Path) -> str:
    """Show a git commit or object.

    Args:
        args: Dictionary with keys:
            - ref: Git reference (commit hash, branch, tag)
            - path: Optional path to show specific file at that ref
            - stat: Show diffstat only (default: False)

    Returns:
        Git show output as string

    Raises:
        ToolError: If git command fails
        SecurityError: If validation fails
    """
    if "ref" not in args:
        raise ToolError("ref parameter is required")

    ref = args["ref"]
    validate_git_ref(ref)

    cmd = ["git", "show"]

    if args.get("stat"):
        cmd.append("--stat")

    # Construct the ref:path or just ref
    if "path" in args:
        path = validate_path(args["path"], git_root)
        # Use relative path for git show
        rel_path = path.relative_to(git_root)
        cmd.append(f"{ref}:{rel_path}")
    else:
        cmd.append(ref)

    try:
        result = subprocess.run(
            cmd,
            cwd=git_root,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise ToolError("git show timed out after 30 seconds")
    except subprocess.CalledProcessError as e:
        raise ToolError(f"git show failed: {e.stderr}")


def tool_grep(args: dict[str, Any], git_root: Path) -> str:
    """Search for pattern in files using grep.

    Args:
        args: Dictionary with keys:
            - pattern: Search pattern (required)
            - path: File or directory path (default: current directory)
            - recursive: Recursive search (default: True)
            - ignore_case: Case-insensitive search (default: False)
            - max_count: Maximum matches per file (default: 100)
            - context: Lines of context (default: 0)

    Returns:
        Grep output as string

    Raises:
        ToolError: If grep fails
        SecurityError: If validation fails
    """
    if "pattern" not in args:
        raise ToolError("pattern parameter is required")

    pattern = args["pattern"]
    path = validate_path(args.get("path", "."), git_root)

    cmd = ["grep", "--color=never"]

    if args.get("ignore_case", False):
        cmd.append("-i")

    if args.get("recursive", True) and path.is_dir():
        cmd.append("-r")

    max_count = args.get("max_count", 100)
    if not isinstance(max_count, int) or max_count < 0:
       raise ToolError("max_count must be a non-negative integer")
    if max_count > 0:
        cmd.extend(["-m", str(max_count)])

    context = args.get("context", 0)
    if not isinstance(context, int) or context < 0 or context > 100:
        raise ToolError(
            "context must be a non-negative integer not greater than 100")
    cmd.extend(["-C", str(context)])

    # Use -- to prevent pattern from being interpreted as an option
    cmd.extend(["--", pattern, str(path)])

    try:
        result = subprocess.run(
            cmd,
            cwd=git_root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        # grep returns 1 if no matches, which is not an error
        if result.returncode not in (0, 1):
            raise ToolError(f"grep failed: {result.stderr}")
        return result.stdout
    except subprocess.TimeoutExpired:
        raise ToolError("grep timed out after 30 seconds")


def tool_awk(args: dict[str, Any], git_root: Path) -> str:
    """Execute awk for text processing (read-only).

    Args:
        args: Dictionary with keys:
            - program: AWK program (required)
            - path: File path (required)

    Returns:
        AWK output as string

    Raises:
        ToolError: If awk fails
        SecurityError: If validation fails or program attempts writes
    """
    if "program" not in args or "path" not in args:
        raise ToolError("program and path parameters are required")

    program = args["program"]
    path = validate_path(args["path"], git_root)

    # Security: Disallow dangerous awk features
    # Block system(), print/printf redirects, pipes, and getline
    dangerous_patterns = [
        r'system\s*\(',
        r'(print|printf)\s*(.*\s*)>\s*',  # any print/printf redirect (with/without quotes)
        r'(?<![|&])\|(?![|&])\s*', # pipe not preceded/followed by another | or &
        r'getline',  # all getline operations
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, program):
            raise SecurityError(f"AWK program contains forbidden pattern: {pattern}")

    if not path.exists():
        raise ToolError(f"File not found: {path}")

    cmd = ["awk", program, str(path)]

    try:
        result = subprocess.run(
            cmd,
            cwd=git_root,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise ToolError("awk timed out after 30 seconds")
    except subprocess.CalledProcessError as e:
        raise ToolError(f"awk failed: {e.stderr}")


def tool_sed(args: dict[str, Any], git_root: Path) -> str:
    """Execute sed for text processing (read-only).

    Args:
        args: Dictionary with keys:
            - program: sed program (required)
            - path: File path (required)

    Returns:
        sed output as string

    Raises:
        ToolError: If sed fails
        SecurityError: If validation fails or program attempts writes
    """
    if "program" not in args or "path" not in args:
        raise ToolError("program and path parameters are required")

    program = args["program"]
    path = validate_path(args["path"], git_root)

    # Security: Force read-only mode, disallow write/execute commands
    # Block w (write), W (Write), e (execute), r/R (read from file), Q (quit with code)
    dangerous_patterns = [
        r'[wWeRQ]\s',  # write, Write, execute, Read, Quit
        r'\d+[wWeRQ]$',  # write/execute/read/quit with address
        r'[rR][/\s]',  # read from file (with or without whitespace)
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, program):
            raise SecurityError(f"sed program contains forbidden pattern: {pattern}")

    if not path.exists():
        raise ToolError(f"File not found: {path}")

    # Always use -n (suppress automatic printing) to prevent side effects
    cmd = ["sed", "-n", program, str(path)]

    try:
        result = subprocess.run(
            cmd,
            cwd=git_root,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise ToolError("sed timed out after 30 seconds")
    except subprocess.CalledProcessError as e:
        raise ToolError(f"sed failed: {e.stderr}")


def tool_file_read(args: dict[str, Any], git_root: Path) -> str:
    """Read contents of a file.

    Args:
        args: Dictionary with keys:
            - path: File path (required)
            - max_size: Maximum file size in bytes (default: 1MB)
            - encoding: Text encoding (default: utf-8)

    Returns:
        File contents as string

    Raises:
        ToolError: If file read fails
        SecurityError: If validation fails
    """
    if "path" not in args:
        raise ToolError("path parameter is required")

    path = validate_path(args["path"], git_root)
    max_size = args.get("max_size", 1024 * 1024)  # 1MB default
    encoding = args.get("encoding", "utf-8")

    if not path.exists():
        raise ToolError(f"File not found: {path}")

    if not path.is_file():
        raise ToolError(f"Not a file: {path}")

    # Check file size
    file_size = path.stat().st_size
    if file_size > max_size:
        raise ToolError(
            f"File too large: {file_size} bytes (max: {max_size})"
        )

    try:
        # Use errors='replace' to handle non-UTF8 bytes gracefully
        return path.read_text(encoding=encoding, errors='replace')
    except Exception as e:
        raise ToolError(f"Failed to read file: {e}") from e


# Tool definitions for Anthropic API
TOOL_DEFINITIONS = [
    {
        "name": "git_log",
        "description": "View git commit history with optional filters. Use this to understand recent changes, find related commits, or trace the history of specific files.",
        "input_schema": {
            "type": "object",
            "properties": {
                "max_count": {
                    "type": "integer",
                    "description": "Maximum number of commits to show (1-100, default: 20)",
                    "minimum": 1,
                    "maximum": 100,
                },
                "since": {
                    "type": "string",
                    "description": "Show commits more recent than date (e.g., '2 weeks ago', '2024-01-01')",
                },
                "until": {
                    "type": "string",
                    "description": "Show commits older than date",
                },
                "path": {
                    "type": "string",
                    "description": "Only show commits affecting this file path",
                },
                "grep": {
                    "type": "string",
                    "description": "Only show commits with messages matching this pattern",
                },
                "author": {
                    "type": "string",
                    "description": "Only show commits by this author",
                },
                "oneline": {
                    "type": "boolean",
                    "description": "Use compact one-line format (default: false)",
                },
            },
        },
    },
    {
        "name": "git_show",
        "description": "Show the contents of a git commit or a specific file at a given commit. Use this to examine what changed in a specific commit or to view historical file contents.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ref": {
                    "type": "string",
                    "description": "Git reference (commit hash, branch name, tag, or HEAD~N)",
                },
                "path": {
                    "type": "string",
                    "description": "Optional: specific file path to show at this ref",
                },
                "stat": {
                    "type": "boolean",
                    "description": "Show only diffstat (default: false)",
                },
            },
            "required": ["ref"],
        },
    },
    {
        "name": "grep",
        "description": "Search for text patterns in files. Use this to find specific code patterns, function definitions, or configuration values.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Search pattern (supports regex)",
                },
                "path": {
                    "type": "string",
                    "description": "File or directory to search (default: current directory)",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Search recursively in directories (default: true)",
                },
                "ignore_case": {
                    "type": "boolean",
                    "description": "Case-insensitive search (default: false)",
                },
                "max_count": {
                    "type": "integer",
                    "description": "Maximum matches per file (default: 100)",
                },
                "context": {
                    "type": "integer",
                    "description": "Lines of context around matches (default: 0)",
                },
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "awk",
        "description": "Process text files using AWK (read-only). Use this to extract columns, filter lines, or perform text transformations. Write/execute operations are blocked.",
        "input_schema": {
            "type": "object",
            "properties": {
                "program": {
                    "type": "string",
                    "description": "AWK program to execute",
                },
                "path": {
                    "type": "string",
                    "description": "File to process",
                },
            },
            "required": ["program", "path"],
        },
    },
    {
        "name": "sed",
        "description": "Process text files using sed (read-only). Use this to extract or transform text. Write/execute operations are blocked and -n flag is always enabled.",
        "input_schema": {
            "type": "object",
            "properties": {
                "program": {
                    "type": "string",
                    "description": "sed program to execute (use p command to print)",
                },
                "path": {
                    "type": "string",
                    "description": "File to process",
                },
            },
            "required": ["program", "path"],
        },
    },
    {
        "name": "file_read",
        "description": "Read the contents of a file. Use this to examine source code, documentation, or configuration files.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to read",
                },
                "max_size": {
                    "type": "integer",
                    "description": "Maximum file size in bytes (default: 1048576 = 1MB)",
                },
                "encoding": {
                    "type": "string",
                    "description": "Text encoding (default: utf-8)",
                },
            },
            "required": ["path"],
        },
    },
]


# Map tool names to handler functions
TOOL_HANDLERS = {
    "git_log": tool_git_log,
    "git_show": tool_git_show,
    "grep": tool_grep,
    "awk": tool_awk,
    "sed": tool_sed,
    "file_read": tool_file_read,
}


def execute_tool(tool_name: str, tool_args: dict[str, Any]) -> str:
    """Execute a tool and return its output.

    Args:
        tool_name: Name of the tool to execute
        tool_args: Arguments for the tool

    Returns:
        Tool output as string

    Raises:
        ToolError: If tool execution fails
        SecurityError: If security validation fails
    """
    if tool_name not in TOOL_HANDLERS:
        raise ToolError(f"Unknown tool: {tool_name}")

    git_root = get_git_root()
    handler = TOOL_HANDLERS[tool_name]

    try:
        return handler(tool_args, git_root)
    except (ToolError, SecurityError):
        raise
    except Exception as e:
        raise ToolError(f"Tool execution failed: {e}") from e


def convert_tools_to_openai_format(anthropic_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert Anthropic tool definitions to OpenAI function calling format.

    Args:
        anthropic_tools: List of tool definitions in Anthropic format

    Returns:
        List of tool definitions in OpenAI format
    """
    openai_tools = []
    for tool in anthropic_tools:
        openai_tool = {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["input_schema"],
            }
        }
        openai_tools.append(openai_tool)
    return openai_tools


def get_tools_for_provider(provider: str) -> list[dict[str, Any]]:
    """Get tool definitions in the format required by the provider.

    Args:
        provider: Provider name (anthropic, openai, xai, google)

    Returns:
        List of tool definitions in provider-specific format
    """
    if provider == "anthropic":
        return TOOL_DEFINITIONS
    elif provider in ("openai", "xai"):
        return convert_tools_to_openai_format(TOOL_DEFINITIONS)
    else:
        # Google Gemini uses a different format, not yet implemented
        return []
