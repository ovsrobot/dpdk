#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger
#
# dpdk-checkpatch.py - Check patches for common style issues
#
# This is a standalone Python replacement for the DPDK checkpatches.sh
# script that previously wrapped the Linux kernel's checkpatch.pl.
#
# Usage examples:
#   # Check patch files
#   dpdk-checkpatch.py *.patch
#
#   # Check patches before applying
#   dpdk-checkpatch.py *.patch && git am *.patch
#
#   # Check commits since origin/main
#   dpdk-checkpatch.py
#
#   # Quiet mode for scripting
#   if dpdk-checkpatch.py -q "$patch"; then
#       echo "Clean, applying..."
#       git am "$patch"
#   else
#       echo "Issues found, skipping"
#   fi
#
#   # Verbose output with context
#   dpdk-checkpatch.py -v my-feature.patch

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

VERSION = "1.0"

# Default configuration
DEFAULT_LINE_LENGTH = 100
DEFAULT_CODESPELL_DICT = "/usr/share/codespell/dictionary.txt"


@dataclass
class CheckResult:
    """Result of a single check."""
    level: str  # ERROR, WARNING, CHECK
    type_name: str
    message: str
    filename: str = ""
    line_num: int = 0
    line_content: str = ""


@dataclass
class PatchInfo:
    """Information extracted from a patch."""
    subject: str = ""
    author: str = ""
    author_email: str = ""
    signoffs: list = field(default_factory=list)
    files: list = field(default_factory=list)
    added_lines: dict = field(default_factory=dict)  # filename -> [(line_num, content)]
    context_before: dict = field(default_factory=dict)  # filename -> {line_num: context_line}
    has_fixes_tag: bool = False
    fixes_commits: list = field(default_factory=list)


class CheckPatch:
    """Main class for checking patches."""

    def __init__(self, config: dict):
        self.config = config
        self.results: list[CheckResult] = []
        self.errors = 0
        self.warnings = 0
        self.checks = 0
        self.lines_checked = 0

        # Load codespell dictionary if enabled
        self.spelling_dict = {}
        if config.get("codespell"):
            self._load_codespell_dict()

        # Forbidden token rules for DPDK
        self.forbidden_rules = self._init_forbidden_rules()

    def _load_codespell_dict(self) -> None:
        """Load the codespell dictionary."""
        dict_path = self.config.get("codespell_file")

        if not dict_path:
            # Search common locations for the dictionary
            search_paths = [
                DEFAULT_CODESPELL_DICT,
                "/usr/local/lib/python3.12/dist-packages/codespell_lib/data/dictionary.txt",
                "/usr/local/lib/python3.11/dist-packages/codespell_lib/data/dictionary.txt",
                "/usr/local/lib/python3.10/dist-packages/codespell_lib/data/dictionary.txt",
                "/usr/lib/python3/dist-packages/codespell_lib/data/dictionary.txt",
            ]

            # Also try to find it via codespell module
            try:
                import codespell_lib
                module_path = os.path.join(
                    os.path.dirname(codespell_lib.__file__),
                    'data', 'dictionary.txt'
                )
                search_paths.insert(0, module_path)
            except ImportError:
                pass

            for path in search_paths:
                if os.path.exists(path):
                    dict_path = path
                    break

        if not dict_path or not os.path.exists(dict_path):
            return

        try:
            with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("->")
                    if len(parts) >= 2:
                        wrong = parts[0].strip().lower()
                        correct = parts[1].strip().split(",")[0].strip()
                        self.spelling_dict[wrong] = correct
        except IOError:
            pass

    def _init_forbidden_rules(self) -> list:
        """Initialize DPDK-specific forbidden token rules."""
        return [
            # Refrain from new calls to RTE_LOG in libraries
            {
                "folders": ["lib"],
                "patterns": [r"RTE_LOG\("],
                "message": "Prefer RTE_LOG_LINE",
            },
            # Refrain from new calls to RTE_LOG in drivers
            {
                "folders": ["drivers"],
                "skip_files": [r".*osdep\.h$"],
                "patterns": [r"RTE_LOG\(", r"RTE_LOG_DP\(", r"rte_log\("],
                "message": "Prefer RTE_LOG_LINE/RTE_LOG_DP_LINE",
            },
            # No output on stdout or stderr
            {
                "folders": ["lib", "drivers"],
                "patterns": [r"\bprintf\b", r"fprintf\(stdout,", r"fprintf\(stderr,"],
                "message": "Writing to stdout or stderr",
            },
            # Refrain from rte_panic() and rte_exit()
            {
                "folders": ["lib", "drivers"],
                "patterns": [r"rte_panic\(", r"rte_exit\("],
                "message": "Using rte_panic/rte_exit",
            },
            # Don't call directly install_headers()
            {
                "folders": ["lib", "drivers"],
                "patterns": [r"\binstall_headers\b"],
                "message": "Using install_headers()",
            },
            # Refrain from using compiler attribute without common macro
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "skip_files": [r"lib/eal/include/rte_common\.h"],
                "patterns": [r"__attribute__"],
                "message": "Using compiler attribute directly",
            },
            # Check %l or %ll format specifier
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"%ll*[xud]"],
                "message": "Using %l format, prefer %PRI*64 if type is [u]int64_t",
            },
            # Refrain from 16/32/64 bits rte_atomicNN_xxx()
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"rte_atomic[0-9][0-9]_.*\("],
                "message": "Using rte_atomicNN_xxx",
            },
            # Refrain from rte_smp_[r/w]mb()
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"rte_smp_(r|w)?mb\("],
                "message": "Using rte_smp_[r/w]mb",
            },
            # Refrain from __sync_xxx builtins
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"__sync_.*\("],
                "message": "Using __sync_xxx builtins",
            },
            # Refrain from __rte_atomic_thread_fence()
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"__rte_atomic_thread_fence\("],
                "message": "Using __rte_atomic_thread_fence, prefer rte_atomic_thread_fence",
            },
            # Refrain from __atomic_xxx builtins
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "skip_files": [r"drivers/common/cnxk/"],
                "patterns": [r"__atomic_.*\(", r"__ATOMIC_(RELAXED|CONSUME|ACQUIRE|RELEASE|ACQ_REL|SEQ_CST)"],
                "message": "Using __atomic_xxx/__ATOMIC_XXX built-ins, prefer rte_atomic_xxx/rte_memory_order_xxx",
            },
            # Refrain from some pthread functions
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"pthread_(create|join|detach|set(_?name_np|affinity_np)|attr_set(inheritsched|schedpolicy))\("],
                "message": "Using pthread functions, prefer rte_thread",
            },
            # Forbid use of __reserved
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"\b__reserved\b"],
                "message": "Using __reserved",
            },
            # Forbid use of __alignof__
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"\b__alignof__\b"],
                "message": "Using __alignof__, prefer C11 alignof",
            },
            # Forbid use of __typeof__
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"\b__typeof__\b"],
                "message": "Using __typeof__, prefer typeof",
            },
            # Forbid use of __builtin_*
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "skip_files": [r"lib/eal/", r"drivers/.*/base/", r"drivers/.*osdep\.h$"],
                "patterns": [r"\b__builtin_"],
                "message": "Using __builtin helpers, prefer EAL macros",
            },
            # Forbid inclusion of linux/pci_regs.h
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"include.*linux/pci_regs\.h"],
                "message": "Using linux/pci_regs.h, prefer rte_pci.h",
            },
            # Forbid variadic argument pack extension in macros
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"#\s*define.*[^(,\s]\.\.\.[\s]*\)"],
                "message": "Do not use variadic argument pack in macros",
            },
            # Forbid __rte_packed_begin with enums
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "patterns": [r"enum.*__rte_packed_begin"],
                "message": "Using __rte_packed_begin with enum is not allowed",
            },
            # Forbid use of #pragma
            {
                "folders": ["lib", "drivers", "app", "examples"],
                "skip_files": [r"lib/eal/include/rte_common\.h"],
                "patterns": [r"(#pragma|_Pragma)"],
                "message": "Using compilers pragma is not allowed",
            },
            # Forbid experimental build flag except in examples
            {
                "folders": ["lib", "drivers", "app"],
                "patterns": [r"-DALLOW_EXPERIMENTAL_API", r"allow_experimental_apis"],
                "message": "Using experimental build flag for in-tree compilation",
            },
            # Refrain from using RTE_LOG_REGISTER for drivers and libs
            {
                "folders": ["lib", "drivers"],
                "patterns": [r"\bRTE_LOG_REGISTER\b"],
                "message": "Using RTE_LOG_REGISTER, prefer RTE_LOG_REGISTER_(DEFAULT|SUFFIX)",
            },
            # Forbid non-internal thread in drivers and libs
            {
                "folders": ["lib", "drivers"],
                "patterns": [r"rte_thread_(set_name|create_control)\("],
                "message": "Prefer rte_thread_(set_prefixed_name|create_internal_control)",
            },
        ]

    def add_result(self, level: str, type_name: str, message: str,
                   filename: str = "", line_num: int = 0, line_content: str = "") -> None:
        """Add a check result."""
        result = CheckResult(
            level=level,
            type_name=type_name,
            message=message,
            filename=filename,
            line_num=line_num,
            line_content=line_content
        )
        self.results.append(result)

        if level == "ERROR":
            self.errors += 1
        elif level == "WARNING":
            self.warnings += 1
        else:
            self.checks += 1

    def parse_patch(self, content: str) -> PatchInfo:
        """Parse a patch and extract information."""
        info = PatchInfo()
        current_file = ""
        in_diff = False
        line_num_in_new = 0

        lines = content.split("\n")
        for i, line in enumerate(lines):
            # Extract subject
            if line.startswith("Subject:"):
                subject = line[8:].strip()
                # Handle multi-line subjects
                j = i + 1
                while j < len(lines) and lines[j].startswith(" "):
                    subject += " " + lines[j].strip()
                    j += 1
                info.subject = subject

            # Extract author
            if line.startswith("From:"):
                info.author = line[5:].strip()
                match = re.search(r"<([^>]+)>", info.author)
                if match:
                    info.author_email = match.group(1)

            # Extract Signed-off-by
            match = re.match(r"^Signed-off-by:\s*(.+)$", line, re.IGNORECASE)
            if match:
                info.signoffs.append(match.group(1).strip())

            # Extract Fixes tag
            match = re.match(r"^Fixes:\s*([0-9a-fA-F]+)", line)
            if match:
                info.has_fixes_tag = True
                info.fixes_commits.append(match.group(1))

            # Track files in diff
            if line.startswith("diff --git"):
                match = re.match(r"diff --git a/(\S+) b/(\S+)", line)
                if match:
                    current_file = match.group(2)
                    if current_file not in info.files:
                        info.files.append(current_file)
                    info.added_lines[current_file] = []
                in_diff = True

            # Track hunks
            if line.startswith("@@"):
                match = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
                if match:
                    line_num_in_new = int(match.group(1))
                continue

            # Track added lines
            if in_diff and current_file:
                if line.startswith("+") and not line.startswith("+++"):
                    info.added_lines[current_file].append((line_num_in_new, line[1:]))
                    line_num_in_new += 1
                elif line.startswith("-"):
                    pass  # Deleted line, don't increment
                elif not line.startswith("\\"):
                    # Context line - store it for reference by line number
                    if current_file not in info.context_before:
                        info.context_before[current_file] = {}
                    info.context_before[current_file][line_num_in_new] = line[1:] if line.startswith(" ") else line
                    line_num_in_new += 1

        return info

    def check_line_length(self, patch_info: PatchInfo) -> None:
        """Check for lines exceeding maximum length."""
        max_len = self.config.get("max_line_length", DEFAULT_LINE_LENGTH)

        for filename, lines in patch_info.added_lines.items():
            for line_num, content in lines:
                # Skip strings that span multiple lines
                if len(content) > max_len:
                    # Don't warn about long strings or URLs
                    if '\"' in content and content.count('\"') >= 2:
                        continue
                    if "http://" in content or "https://" in content:
                        continue
                    # Check if it's a comment line
                    if content.strip().startswith("/*") or content.strip().startswith("*") or content.strip().startswith("//"):
                        self.add_result(
                            "WARNING", "LONG_LINE_COMMENT",
                            f"line length of {len(content)} exceeds {max_len} columns",
                            filename, line_num, content
                        )
                    else:
                        self.add_result(
                            "WARNING", "LONG_LINE",
                            f"line length of {len(content)} exceeds {max_len} columns",
                            filename, line_num, content
                        )

    def check_trailing_whitespace(self, patch_info: PatchInfo) -> None:
        """Check for trailing whitespace."""
        for filename, lines in patch_info.added_lines.items():
            for line_num, content in lines:
                if content != content.rstrip():
                    self.add_result(
                        "WARNING", "TRAILING_WHITESPACE",
                        "trailing whitespace",
                        filename, line_num, content
                    )

    def check_tabs_spaces(self, patch_info: PatchInfo) -> None:
        """Check for space before tab and mixed indentation."""
        for filename, lines in patch_info.added_lines.items():
            for line_num, content in lines:
                if " \t" in content:
                    self.add_result(
                        "WARNING", "SPACE_BEFORE_TAB",
                        "space before tab in indent",
                        filename, line_num, content
                    )

    def check_signoff(self, patch_info: PatchInfo) -> None:
        """Check for Signed-off-by line."""
        if not patch_info.signoffs:
            self.add_result(
                "ERROR", "MISSING_SIGN_OFF",
                "Missing Signed-off-by: line(s)"
            )

    def check_coding_style(self, patch_info: PatchInfo) -> None:
        """Check various coding style issues."""
        for filename, lines in patch_info.added_lines.items():
            # Skip non-C files for most checks
            is_c_file = filename.endswith((".c", ".h"))
            is_c_source = filename.endswith(".c")
            is_header = filename.endswith(".h")

            prev_line = ""
            indent_stack = []
            context_before = patch_info.context_before.get(filename, {})
            for line_num, content in lines:
                self.lines_checked += 1

                # Check if the line immediately before this one (which may be
                # a context line from the patch) ended with backslash continuation
                prev_context = context_before.get(line_num - 1, "")
                in_macro_continuation = prev_context.rstrip().endswith("\\")

                if is_c_file:
                    # Check for extern function declarations in .c files
                    # Only flag functions (have parentheses), not data
                    if is_c_source and re.match(r"^\s*extern\b", content):
                        if re.search(r'\(', content):
                            self.add_result(
                                "WARNING", "AVOID_EXTERNS",
                                "extern is not needed for function declarations",
                                filename, line_num, content
                            )

                    # Check for unnecessary break after goto/return/continue
                    # Only flag if the previous statement is unconditional (not inside an if)
                    if re.match(r"^\s*break\s*;", content):
                        # Check if previous line is an unconditional return/goto/continue
                        # It's unconditional if it starts at the same or lower indentation as break
                        # or if it's a plain return/goto not inside an if block
                        prev_stripped = prev_line.strip() if prev_line else ""
                        if re.match(r"^(goto\s+\w+|return\b|continue)\s*[^;]*;\s*$", prev_stripped):
                            # Check indentation - if prev line has same or less indentation, it's unconditional
                            break_indent = len(content) - len(content.lstrip())
                            prev_indent = len(prev_line) - len(prev_line.lstrip()) if prev_line else 0
                            # Only flag if the return/goto is at the same indentation level
                            # (meaning it's not inside a nested if block)
                            if prev_indent <= break_indent:
                                self.add_result(
                                    "WARNING", "UNNECESSARY_BREAK",
                                    "break is not useful after a goto or return",
                                    filename, line_num, content
                                )

                    # STRNCPY: should use strlcpy
                    if re.search(r"\bstrncpy\s*\(", content):
                        self.add_result(
                            "WARNING", "STRNCPY",
                            "Prefer strlcpy over strncpy - see: https://lore.kernel.org/r/CAHk-=wgfRnXz0W3D37d01q3JFkr_i_uTL=V6A6G1oUZcprmknw@mail.gmail.com/",
                            filename, line_num, content
                        )

                    # STRCPY: unsafe string copy
                    if re.search(r"\bstrcpy\s*\(", content):
                        self.add_result(
                            "ERROR", "STRCPY",
                            "strcpy is unsafe - use strlcpy or snprintf",
                            filename, line_num, content
                        )

                    # Check for complex macros without proper enclosure
                    # Note: Compound literal macros like (type[]){...} are valid C99
                    # and commonly used in DPDK, so we don't flag those.
                    # Only flag macros with multiple statements without do-while wrapping.
                    if re.match(r"^\s*#\s*define\s+\w+\s*\([^)]*\)\s+\{", content):
                        # Macro body starts with { but is not a compound literal
                        # Check if it's missing do { } while(0)
                        if not re.search(r"\bdo\s*\{", content):
                            self.add_result(
                                "ERROR", "COMPLEX_MACRO",
                                "Macros with complex values should be enclosed in parentheses or do { } while(0)",
                                filename, line_num, content
                            )

                    # SPACING: missing space before ( in control statements
                    if re.search(r"\b(if|while|for|switch)\(", content):
                        self.add_result(
                            "WARNING", "SPACING",
                            "space required before the open parenthesis '('",
                            filename, line_num, content
                        )

                    # SPACING: space prohibited after open square bracket
                    if re.search(r"\[\s+[^\]]", content) and not re.search(r"\[\s*\]", content):
                        self.add_result(
                            "WARNING", "SPACING",
                            "space prohibited after that open square bracket '['",
                            filename, line_num, content
                        )

                    # SPACING: space prohibited before close square bracket
                    if re.search(r"[^\[]\s+\]", content):
                        self.add_result(
                            "WARNING", "SPACING",
                            "space prohibited before that close square bracket ']'",
                            filename, line_num, content
                        )

                    # RETURN_PARENTHESES: return with parentheses
                    if re.search(r"\breturn\s*\([^;]+\)\s*;", content):
                        # Avoid false positives for:
                        # - function calls: return (func())
                        # - casts: return (type)expr or return (type)(expr)
                        if not re.search(r"\breturn\s*\(\s*\w+\s*\([^)]*\)\s*\)\s*;", content) and \
                           not re.search(r"\breturn\s+\([a-zA-Z_][\w\s\*]*\)", content):
                            self.add_result(
                                "WARNING", "RETURN_PARENTHESES",
                                "return is not a function, parentheses are not required",
                                filename, line_num, content
                            )

                    # BRACES: single statement blocks that need braces
                    # Check for if/else/while/for without braces on multiline
                    if re.match(r"^\s*(if|else\s+if|while|for)\s*\([^{]*$", content):
                        # Control statement without opening brace - check next line
                        pass  # Would need lookahead

                    # INITIALISED_STATIC: static initialized to 0/NULL
                    if re.match(r"^\s*static\s+.*=\s*(0|NULL|0L|0UL|0ULL|0LL)\s*;", content):
                        self.add_result(
                            "WARNING", "INITIALISED_STATIC",
                            "do not initialise statics to 0 or NULL",
                            filename, line_num, content
                        )

                    # GLOBAL_INITIALISERS: global initialized to 0/NULL
                    if re.match(r"^[a-zA-Z_][a-zA-Z0-9_\s\*]*=\s*(0|NULL|0L|0UL|0ULL|0LL)\s*;", content):
                        if not re.match(r"^\s*static\s+", content):
                            self.add_result(
                                "WARNING", "GLOBAL_INITIALISERS",
                                "do not initialise globals to 0 or NULL",
                                filename, line_num, content
                            )

                    # Note: DEEP_INDENTATION check removed - without full brace
                    # nesting tracking (as in checkpatch.pl), tab counting produces
                    # too many false positives in legitimate code like switch/case
                    # blocks and nested loops in driver transmit paths.

                    # TRAILING_STATEMENTS: code on same line as } OR control statement
                    # But allow struct/union member declarations: } name; or } name; /* comment */
                    if re.search(r"\}\s*[a-zA-Z_]", content) and not re.search(r"\}\s*(else|while)\b", content):
                        # Check if this is a struct/union member declaration
                        # Pattern: } identifier; or } identifier[]; or with comment
                        if not re.search(r"\}\s*\w+\s*(\[\d*\])?\s*;\s*(/\*.*\*/|//.*)?\s*$", content):
                            self.add_result(
                                "ERROR", "TRAILING_STATEMENTS",
                                "trailing statements should be on next line",
                                filename, line_num, content
                            )
                    # Also check for if/while/for with statement on same line (not opening brace)
                    # Pattern: if (cond) statement; or if (cond) statement; /* comment */
                    if re.search(r"\b(if|while|for)\s*\([^)]+\)\s+(?![\s{])[^;]*;", content):
                        self.add_result(
                            "ERROR", "TRAILING_STATEMENTS",
                            "trailing statements should be on next line",
                            filename, line_num, content
                        )

                    # CONSTANT_COMPARISON: Yoda conditions (constant on left)
                    if re.search(r'\b(NULL|true|false)\s*[!=]=\s*[&*\w]', content) or \
                       re.search(r'\(\s*0\s*[!=]=\s*[&*\w]', content):
                        self.add_result(
                            "WARNING", "CONSTANT_COMPARISON",
                            "Comparisons should place the constant on the right side",
                            filename, line_num, content
                        )

                    # BRACES: single statement block should not have braces (or vice versa)
                    # Check for if/else/while/for with single statement in braces
                    if re.match(r"^\s*(if|while|for)\s*\([^)]+\)\s*\{\s*$", prev_line):
                        if re.match(r"^\s*\w.*;\s*$", content) and not re.search(r"^\s*(if|else|while|for|switch|case|default|return\s*;)", content):
                            # Check if next line is just closing brace - would need lookahead
                            pass

                    # ONE_SEMICOLON: double semicolon
                    if re.search(r";;", content) and not re.search(r"for\s*\([^)]*;;", content):
                        self.add_result(
                            "WARNING", "ONE_SEMICOLON",
                            "Statements terminations use 1 semicolon",
                            filename, line_num, content
                        )

                    # CODE_INDENT/LEADING_SPACE: spaces used for indentation instead of tabs
                    if re.match(r"^    +[^\s]", content) and not content.strip().startswith("*"):
                        # Line starts with spaces (not tabs) - but allow for alignment in comments
                        self.add_result(
                            "WARNING", "CODE_INDENT",
                            "code indent should use tabs where possible",
                            filename, line_num, content
                        )

                    # LEADING_SPACE: spaces at start of line (more general)
                    if re.match(r"^ +\t", content):
                        self.add_result(
                            "WARNING", "LEADING_SPACE",
                            "please, no spaces at the start of a line",
                            filename, line_num, content
                        )

                    # LINE_CONTINUATIONS: backslash continuation outside macros
                    # Check if this line has a backslash continuation
                    if content.rstrip().endswith("\\"):
                        # Only flag if not inside a macro definition
                        # A macro context means either:
                        # - This line starts a #define
                        # - The previous line (added or context) was a continuation
                        # - This line is a preprocessor directive
                        is_in_macro = (
                            re.match(r"^\s*#", content) or
                            (prev_line and prev_line.rstrip().endswith("\\")) or
                            in_macro_continuation
                        )
                        if not is_in_macro:
                            self.add_result(
                                "WARNING", "LINE_CONTINUATIONS",
                                "Avoid unnecessary line continuations",
                                filename, line_num, content
                            )

                    # FUNCTION_WITHOUT_ARGS: empty parens instead of (void)
                    if is_header and re.search(r"\b\w+\s*\(\s*\)\s*;", content):
                        if not re.search(r"\b(while|if|for|switch|return)\s*\(\s*\)", content):
                            self.add_result(
                                "ERROR", "FUNCTION_WITHOUT_ARGS",
                                "Bad function definition - use (void) instead of ()",
                                filename, line_num, content
                            )

                    # INLINE_LOCATION: inline should come after storage class
                    if re.match(r"^\s*inline\s+(static|extern)", content):
                        self.add_result(
                            "ERROR", "INLINE_LOCATION",
                            "inline keyword should sit between storage class and type",
                            filename, line_num, content
                        )

                    # STATIC_CONST: const should come after static
                    if re.match(r"^\s*const\s+static\b", content):
                        self.add_result(
                            "WARNING", "STATIC_CONST",
                            "Move const after static - use 'static const'",
                            filename, line_num, content
                        )
                        self.add_result(
                            "WARNING", "STORAGE_CLASS",
                            "storage class should be at the beginning of the declaration",
                            filename, line_num, content
                        )

                    # CONST_CONST: const used twice
                    if re.search(r"\bconst\s+\w+\s+const\b", content):
                        self.add_result(
                            "WARNING", "CONST_CONST",
                            "const used twice - remove duplicate const",
                            filename, line_num, content
                        )

                    # SELF_ASSIGNMENT: x = x (simple variable, not struct members)
                    # Match only simple identifiers, not struct/pointer member access
                    match = re.search(r"^\s*(\w+)\s*=\s*(\w+)\s*;", content)
                    if match and match.group(1) == match.group(2):
                        self.add_result(
                            "WARNING", "SELF_ASSIGNMENT",
                            "Do not use self-assignments to avoid compiler warnings",
                            filename, line_num, content
                        )

                    # PREFER_DEFINED_ATTRIBUTE_MACRO: prefer DPDK/kernel macros over __attribute__
                    attr_macros = {
                        'cold': '__rte_cold',
                        'hot': '__rte_hot', 
                        'noinline': '__rte_noinline',
                        'always_inline': '__rte_always_inline',
                        'unused': '__rte_unused',
                        'packed': '__rte_packed',
                        'aligned': '__rte_aligned',
                        'weak': '__rte_weak',
                        'pure': '__rte_pure',
                    }
                    for attr, replacement in attr_macros.items():
                        if re.search(rf'__attribute__\s*\(\s*\(\s*{attr}\b', content):
                            self.add_result(
                                "WARNING", "PREFER_DEFINED_ATTRIBUTE_MACRO",
                                f"Prefer {replacement} over __attribute__(({attr}))",
                                filename, line_num, content
                            )

                    # POINTER_LOCATION: char* instead of char *
                    if re.search(r"\b(char|int|void|short|long|float|double|unsigned|signed)\*\s+\w", content):
                        self.add_result(
                            "ERROR", "POINTER_LOCATION",
                            "\"foo* bar\" should be \"foo *bar\"",
                            filename, line_num, content
                        )

                    # MACRO_WITH_FLOW_CONTROL: macros with return/goto/break
                    if re.match(r"^\s*#\s*define\s+\w+.*\b(return|goto|break|continue)\b", content):
                        self.add_result(
                            "WARNING", "MACRO_WITH_FLOW_CONTROL",
                            "Macros with flow control statements should be avoided",
                            filename, line_num, content
                        )

                    # MULTISTATEMENT_MACRO_USE_DO_WHILE: macros with multiple statements
                    if re.match(r"^\s*#\s*define\s+\w+\([^)]*\)\s+.*;\s*[^\\]", content):
                        if not re.search(r"do\s*\{", content):
                            self.add_result(
                                "WARNING", "MULTISTATEMENT_MACRO_USE_DO_WHILE",
                                "Macros with multiple statements should use do {} while(0)",
                                filename, line_num, content
                            )

                    # MULTISTATEMENT_MACRO_USE_DO_WHILE: macros starting with if
                    if re.match(r"^\s*#\s*define\s+\w+\([^)]*\)\s+if\s*\(", content):
                        self.add_result(
                            "ERROR", "MULTISTATEMENT_MACRO_USE_DO_WHILE",
                            "Macros starting with if should be enclosed by a do - while loop",
                            filename, line_num, content
                        )

                    # Multiple statements on one line (skip comments and strings)
                    stripped_content = content.strip()
                    if re.search(r";\s*[a-zA-Z_]", content) and "for" not in content:
                        # Skip if line is a comment
                        if not (stripped_content.startswith("/*") or 
                                stripped_content.startswith("*") or 
                                stripped_content.startswith("//")):
                            # Skip if the semicolon is inside a string or comment
                            # Remove strings and comments before checking
                            code_only = re.sub(r'"[^"]*"', '""', content)  # Remove string contents
                            code_only = re.sub(r'/\*.*?\*/', '', code_only)  # Remove /* */ comments
                            code_only = re.sub(r'//.*$', '', code_only)  # Remove // comments
                            if re.search(r";\s*[a-zA-Z_]", code_only):
                                self.add_result(
                                    "CHECK", "MULTIPLE_STATEMENTS",
                                    "multiple statements on one line",
                                    filename, line_num, content
                                )

                    # Check for C99 comments in headers that should use C89
                    if is_header and "//" in content:
                        # Only flag if not in a string
                        stripped = re.sub(r'"[^"]*"', '', content)
                        if "//" in stripped:
                            self.add_result(
                                "CHECK", "C99_COMMENTS",
                                "C99 // comments are acceptable but /* */ is preferred in headers",
                                filename, line_num, content
                            )

                    # BLOCK_COMMENT_STYLE: block comments style issues
                    # Leading /* on its own line (but allow Doxygen /** style)
                    if re.match(r"^\s*/\*\*+\s*$", content):
                        # Allow /** (Doxygen) but not /*** or more
                        if not re.match(r"^\s*/\*\*\s*$", content):
                            self.add_result(
                                "WARNING", "BLOCK_COMMENT_STYLE",
                                "Block comments should not use a leading /* on a line by itself",
                                filename, line_num, content
                            )
                    # Trailing */ on separate line after block comment
                    if re.match(r"^\s*\*+/\s*$", content) and prev_line.strip().startswith("*"):
                        pass  # This is actually acceptable
                    # Block with trailing */ but content before it (like === */)
                    if re.search(r"\S\s*=+\s*\*/\s*$", content):
                        self.add_result(
                            "WARNING", "BLOCK_COMMENT_STYLE",
                            "Block comments use a trailing */ on a separate line",
                            filename, line_num, content
                        )

                    # REPEATED_WORD: check for repeated words
                    words = re.findall(r'\b(\w+)\s+\1\b', content, re.IGNORECASE)
                    for word in words:
                        word_lower = word.lower()
                        # Skip common valid repeated patterns
                        if word_lower not in ('that', 'had', 'long', 'int', 'short'):
                            self.add_result(
                                "WARNING", "REPEATED_WORD",
                                f"Possible repeated word: '{word}'",
                                filename, line_num, content
                            )

                    # STRING_FRAGMENTS: unnecessary string concatenation like "foo" "bar"
                    # Must have closing quote, whitespace, opening quote pattern
                    if re.search(r'"\s*"\s*[^)]', content) and not re.search(r'#\s*define', content):
                        # Verify it's actually two separate strings being concatenated
                        # by checking for the pattern: "..." "..."
                        if re.search(r'"[^"]*"\s+"[^"]*"', content):
                            self.add_result(
                                "CHECK", "STRING_FRAGMENTS",
                                "Consecutive strings are generally better as a single string",
                                filename, line_num, content
                            )

                prev_line = content

    def check_spelling(self, patch_info: PatchInfo) -> None:
        """Check for spelling errors using codespell dictionary."""
        for filename, lines in patch_info.added_lines.items():
            for line_num, content in lines:
                # REPEATED_WORD check for non-C files (C files handled in check_coding_style)
                if not filename.endswith((".c", ".h")):
                    words = re.findall(r'\b(\w+)\s+\1\b', content, re.IGNORECASE)
                    for word in words:
                        word_lower = word.lower()
                        if word_lower not in ('that', 'had', 'long', 'int', 'short'):
                            self.add_result(
                                "WARNING", "REPEATED_WORD",
                                f"Possible repeated word: '{word}'",
                                filename, line_num, content
                            )

                # Spelling check
                if self.spelling_dict:
                    # Common abbreviations that should not be flagged as typos
                    abbreviations = {
                        'nd', 'ns', 'na', 'ra', 'rs',  # IPv6 Neighbor Discovery
                        'tx', 'rx', 'id', 'io', 'ip',  # Common networking
                        'tcp', 'udp', 'arp', 'dns',    # Protocols  
                        'hw', 'sw', 'fw',              # Hardware/Software/Firmware
                        'src', 'dst', 'ptr', 'buf',    # Common code abbreviations
                        'cfg', 'ctx', 'idx', 'cnt',    # Config/Context/Index/Count
                        'len', 'num', 'max', 'min',    # Length/Number/Max/Min
                        'prev', 'next', 'curr',        # Previous/Next/Current
                        'init', 'fini', 'deinit',      # Initialize/Finish
                        'alloc', 'dealloc', 'realloc', # Memory
                        'endcode',                      # Doxygen tag
                    }
                    # Extract words, but skip contractions (don't, couldn't, etc.)
                    # by removing them before word extraction
                    spell_content = re.sub(r"[a-zA-Z]+n't\b", '', content)
                    spell_content = re.sub(r"[a-zA-Z]+'[a-zA-Z]+", '', spell_content)
                    words = re.findall(r'\b[a-zA-Z]+\b', spell_content)
                    for word in words:
                        lower_word = word.lower()
                        if lower_word in self.spelling_dict and lower_word not in abbreviations:
                            self.add_result(
                                "WARNING", "TYPO_SPELLING",
                                f"'{word}' may be misspelled - perhaps '{self.spelling_dict[lower_word]}'?",
                                filename, line_num, content
                            )

    def check_forbidden_tokens(self, patch_info: PatchInfo) -> None:
        """Check for DPDK-specific forbidden tokens."""
        for filename, lines in patch_info.added_lines.items():
            for rule in self.forbidden_rules:
                # Check if file is in one of the target folders
                in_folder = False
                for folder in rule["folders"]:
                    if filename.startswith(folder + "/") or filename.startswith("b/" + folder + "/"):
                        in_folder = True
                        break

                if not in_folder:
                    continue

                # Check if file should be skipped
                skip = False
                for skip_pattern in rule.get("skip_files", []):
                    if re.search(skip_pattern, filename):
                        skip = True
                        break

                if skip:
                    continue

                # Check each line for forbidden patterns
                for line_num, content in lines:
                    for pattern in rule["patterns"]:
                        if re.search(pattern, content):
                            self.add_result(
                                "WARNING", "FORBIDDEN_TOKEN",
                                rule["message"],
                                filename, line_num, content
                            )
                            break

    def check_experimental_tags(self, patch_info: PatchInfo) -> None:
        """Check __rte_experimental tag placement."""
        for filename, lines in patch_info.added_lines.items():
            for line_num, content in lines:
                if "__rte_experimental" in content:
                    # Should only be in headers
                    if filename.endswith(".c"):
                        self.add_result(
                            "WARNING", "EXPERIMENTAL_TAG",
                            f"Please only put __rte_experimental tags in headers ({filename})",
                            filename, line_num, content
                        )
                    # Should appear alone on the line
                    stripped = content.strip()
                    if stripped != "__rte_experimental":
                        self.add_result(
                            "WARNING", "EXPERIMENTAL_TAG",
                            "__rte_experimental must appear alone on the line immediately preceding the return type of a function",
                            filename, line_num, content
                        )

    def check_internal_tags(self, patch_info: PatchInfo) -> None:
        """Check __rte_internal tag placement."""
        for filename, lines in patch_info.added_lines.items():
            for line_num, content in lines:
                if "__rte_internal" in content:
                    # Should only be in headers
                    if filename.endswith(".c"):
                        self.add_result(
                            "WARNING", "INTERNAL_TAG",
                            f"Please only put __rte_internal tags in headers ({filename})",
                            filename, line_num, content
                        )
                    # Should appear alone on the line
                    stripped = content.strip()
                    if stripped != "__rte_internal":
                        self.add_result(
                            "WARNING", "INTERNAL_TAG",
                            "__rte_internal must appear alone on the line immediately preceding the return type of a function",
                            filename, line_num, content
                        )

    def check_aligned_attributes(self, patch_info: PatchInfo) -> None:
        """Check alignment attribute usage."""
        align_tokens = ["__rte_aligned", "__rte_cache_aligned", "__rte_cache_min_aligned"]

        for filename, lines in patch_info.added_lines.items():
            for line_num, content in lines:
                for token in align_tokens:
                    if re.search(rf"\b{token}\b", content):
                        # Should only be used with struct or union
                        if not re.search(rf"\b(struct|union)\s*{token}\b", content):
                            self.add_result(
                                "WARNING", "ALIGNED_ATTRIBUTE",
                                f"Please use {token} only for struct or union types alignment",
                                filename, line_num, content
                            )

    def check_packed_attributes(self, patch_info: PatchInfo) -> None:
        """Check packed attribute usage."""
        begin_count = 0
        end_count = 0

        for filename, lines in patch_info.added_lines.items():
            for line_num, content in lines:
                if "__rte_packed_begin" in content:
                    begin_count += 1
                    # Should be after struct, union, or alignment attributes
                    if not re.search(r"\b(struct|union)\s*__rte_packed_begin\b", content) and \
                       not re.search(r"__rte_cache_aligned\s*__rte_packed_begin", content) and \
                       not re.search(r"__rte_cache_min_aligned\s*__rte_packed_begin", content) and \
                       not re.search(r"__rte_aligned\(.*\)\s*__rte_packed_begin", content):
                        self.add_result(
                            "WARNING", "PACKED_ATTRIBUTE",
                            "Use __rte_packed_begin only after struct, union or alignment attributes",
                            filename, line_num, content
                        )

                if "__rte_packed_end" in content:
                    end_count += 1

        if begin_count != end_count:
            self.add_result(
                "WARNING", "PACKED_ATTRIBUTE",
                "__rte_packed_begin and __rte_packed_end should always be used in pairs"
            )

    def check_patch(self, content: str, patch_file: str = None) -> bool:
        """Run all checks on a patch."""
        self.results = []
        self.errors = 0
        self.warnings = 0
        self.checks = 0
        self.lines_checked = 0

        # Check patch format first
        self.check_patch_format(content, patch_file)

        patch_info = self.parse_patch(content)

        # Run all checks
        self.check_signoff(patch_info)
        self.check_line_length(patch_info)
        self.check_trailing_whitespace(patch_info)
        self.check_tabs_spaces(patch_info)
        self.check_coding_style(patch_info)
        self.check_spelling(patch_info)
        self.check_forbidden_tokens(patch_info)
        self.check_experimental_tags(patch_info)
        self.check_internal_tags(patch_info)
        self.check_aligned_attributes(patch_info)
        self.check_packed_attributes(patch_info)
        self.check_commit_message(patch_info, content)

        return self.errors == 0 and self.warnings == 0

    def check_patch_format(self, content: str, patch_file: str = None) -> None:
        """Check basic patch format for corruption."""
        lines = content.split("\n")

        # Track patch structure
        has_diff = False
        has_hunk = False
        in_hunk = False
        hunk_line = 0

        for i, line in enumerate(lines, 1):
            # Track diff headers
            if line.startswith("diff --git"):
                has_diff = True
                in_hunk = False

            # Parse hunk header
            if line.startswith("@@"):
                has_hunk = True
                in_hunk = True
                hunk_line = i
                # Validate hunk header format
                if not re.match(r"@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", line):
                    self.add_result(
                        "ERROR", "CORRUPTED_PATCH",
                        f"patch seems to be corrupt (malformed hunk header) at line {i}"
                    )

            # End of patch content (signature separator)
            elif line == "-- ":
                in_hunk = False

            # Check for lines that look like they should be in a hunk but aren't prefixed
            elif in_hunk and line and not line.startswith(("+", "-", " ", "\\", "diff ", "@@", "index ", "--- ", "+++ ", "new file", "deleted file", "old mode", "new mode", "rename ", "similarity", "copy ")):
                # This could be a wrapped line or corruption
                # But be careful - empty lines and commit message lines are OK
                if not line.startswith(("From ", "Subject:", "Date:", "Signed-off-by:",
                                       "Acked-by:", "Reviewed-by:", "Tested-by:",
                                       "Fixes:", "Cc:", "---", "Message-Id:")):
                    # Likely a corrupted/wrapped line in the diff
                    self.add_result(
                        "ERROR", "CORRUPTED_PATCH",
                        f"patch seems to be corrupt (line wrapped?) at line {i}"
                    )
                    in_hunk = False  # Stop checking this hunk

        if has_diff and not has_hunk:
            self.add_result(
                "ERROR", "CORRUPTED_PATCH",
                "Patch appears to be corrupted (has diff but no hunks)"
            )

        # Check for DOS line endings
        if "\r\n" in content:
            self.add_result(
                "ERROR", "DOS_LINE_ENDINGS",
                "Patch has DOS line endings, should be UNIX line endings"
            )

    def check_commit_message(self, patch_info: PatchInfo, content: str) -> None:
        """Check commit message for issues."""
        lines = content.split("\n")

        in_commit_msg = False
        commit_msg_lines = []

        for i, line in enumerate(lines):
            if line.startswith("Subject:"):
                in_commit_msg = True
                continue
            if line.startswith("---") or line.startswith("diff --git"):
                in_commit_msg = False
                continue
            if in_commit_msg:
                commit_msg_lines.append((i + 1, line))

        for line_num, line in commit_msg_lines:
            # UNKNOWN_COMMIT_ID: Fixes tag with short or invalid commit ID
            match = re.match(r"^Fixes:\s*([0-9a-fA-F]+)", line)
            if match:
                commit_id = match.group(1)
                if len(commit_id) < 12:
                    self.add_result(
                        "WARNING", "UNKNOWN_COMMIT_ID",
                        f"Commit id '{commit_id}' is too short, use at least 12 characters",
                        line_num=line_num, line_content=line
                    )
                # Check Fixes format: should be Fixes: <hash> ("commit subject")
                if not re.match(r'^Fixes:\s+[0-9a-fA-F]{12,}\s+\("[^"]+"\)\s*$', line):
                    self.add_result(
                        "WARNING", "BAD_FIXES_TAG",
                        "Fixes: tag format should be: Fixes: <12+ char hash> (\"commit subject\")",
                        line_num=line_num, line_content=line
                    )

    def format_results(self, show_types: bool = True) -> str:
        """Format the results for output."""
        output = []

        for result in self.results:
            if result.filename and result.line_num:
                prefix = f"{result.filename}:{result.line_num}:"
            elif result.filename:
                prefix = f"{result.filename}:"
            else:
                prefix = ""

            type_str = f" [{result.type_name}]" if show_types else ""
            output.append(f"{result.level}:{type_str} {result.message}")

            if prefix:
                output.append(f"#  {prefix}")
            if result.line_content:
                output.append(f"+  {result.line_content}")
            output.append("")

        return "\n".join(output)

    def get_summary(self) -> str:
        """Get a summary of the check results."""
        return f"total: {self.errors} errors, {self.warnings} warnings, {self.checks} checks, {self.lines_checked} lines checked"


def split_mbox(content: str) -> list[str]:
    """Split an mbox file into individual messages.
    
    Mbox format uses 'From ' at the start of a line as message separator.
    """
    messages = []
    current = []
    
    for line in content.split('\n'):
        # Standard mbox separator: line starting with "From " followed by
        # an address or identifier and a date
        if line.startswith('From ') and current:
            messages.append('\n'.join(current))
            current = [line]
        else:
            current.append(line)
    
    if current:
        messages.append('\n'.join(current))
    
    return messages


def check_single_patch(checker: CheckPatch, patch_path: Optional[str],
                       commit: Optional[str], verbose: bool, quiet: bool,
                       pre_content: Optional[str] = None) -> bool:
    """Check a single patch file or commit."""
    subject = ""
    content = ""

    if pre_content:
        content = pre_content
    elif patch_path:
        try:
            with open(patch_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except IOError as e:
            print(f"Error reading {patch_path}: {e}", file=sys.stderr)
            return False
    elif commit:
        try:
            result = subprocess.run(
                ["git", "format-patch", "--find-renames", "--no-stat", "--stdout", "-1", commit],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                print(f"Error getting commit {commit}", file=sys.stderr)
                return False
            content = result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error running git: {e}", file=sys.stderr)
            return False
    else:
        content = sys.stdin.read()

    # Extract subject
    match = re.search(r"^Subject:\s*(.+?)(?:\n(?=\S)|\n\n)", content, re.MULTILINE | re.DOTALL)
    if match:
        subject = match.group(1).replace("\n ", " ").strip()

    if verbose:
        print(f"\n### {subject}\n")

    is_clean = checker.check_patch(content, patch_path)
    has_issues = checker.errors > 0 or checker.warnings > 0

    if has_issues or verbose:
        if not verbose and subject:
            print(f"\n### {subject}\n")
        print(checker.format_results(show_types=True))
        print(checker.get_summary())

    return is_clean


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Check patches for DPDK coding style and common issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s patch.diff                Check a patch file
  %(prog)s -n 3                      Check last 3 commits
  %(prog)s -r origin/main..HEAD      Check commits in range
  cat patch.diff | %(prog)s          Check patch from stdin
"""
    )

    parser.add_argument("patches", nargs="*", help="Patch files to check")
    parser.add_argument("-n", type=int, metavar="NUM",
                       help="Check last NUM commits")
    parser.add_argument("-r", "--range", metavar="RANGE",
                       help="Check commits in git range (default: origin/main..)")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Quiet mode - only show summary")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose mode - show all checks")
    parser.add_argument("--max-line-length", type=int, default=DEFAULT_LINE_LENGTH,
                       help=f"Maximum line length (default: {DEFAULT_LINE_LENGTH})")
    parser.add_argument("--codespell", action="store_true", default=True,
                       help="Enable spell checking (default: enabled)")
    parser.add_argument("--no-codespell", dest="codespell", action="store_false",
                       help="Disable spell checking")
    parser.add_argument("--codespellfile", metavar="FILE",
                       help="Path to codespell dictionary")
    parser.add_argument("--show-types", action="store_true", default=True,
                       help="Show message types (default: enabled)")
    parser.add_argument("--no-show-types", dest="show_types", action="store_false",
                       help="Hide message types")

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    # Build configuration
    config = {
        "max_line_length": args.max_line_length,
        "codespell": args.codespell,
        "show_types": args.show_types,
    }

    if args.codespellfile:
        config["codespell_file"] = args.codespellfile

    checker = CheckPatch(config)

    total = 0
    failed = 0

    if args.patches:
        # Check specified patch files
        for patch in args.patches:
            try:
                with open(patch, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except IOError as e:
                print(f"Error reading {patch}: {e}", file=sys.stderr)
                total += 1
                failed += 1
                continue

            # Check if this is an mbox with multiple patches
            messages = split_mbox(content)
            if len(messages) > 1:
                for msg in messages:
                    # Only process messages that contain diffs
                    if 'diff --git' in msg or '---' in msg:
                        total += 1
                        if not check_single_patch(checker, None, None, args.verbose, args.quiet, msg):
                            failed += 1
            else:
                total += 1
                if not check_single_patch(checker, patch, None, args.verbose, args.quiet):
                    failed += 1

    elif args.n or args.range:
        # Check git commits
        if args.n:
            result = subprocess.run(
                ["git", "rev-list", "--reverse", f"--max-count={args.n}", "HEAD"],
                capture_output=True,
                text=True
            )
        else:
            git_range = args.range if args.range else "origin/main.."
            result = subprocess.run(
                ["git", "rev-list", "--reverse", git_range],
                capture_output=True,
                text=True
            )

        if result.returncode != 0:
            print("Error getting git commits", file=sys.stderr)
            sys.exit(1)

        commits = result.stdout.strip().split("\n")
        for commit in commits:
            if commit:
                total += 1
                if not check_single_patch(checker, None, commit, args.verbose, args.quiet):
                    failed += 1

    elif not sys.stdin.isatty():
        # Read from stdin
        total = 1
        if not check_single_patch(checker, None, None, args.verbose, args.quiet):
            failed += 1

    else:
        # Default to checking commits since origin/main
        result = subprocess.run(
            ["git", "rev-list", "--reverse", "origin/main.."],
            capture_output=True,
            text=True
        )

        commits = result.stdout.strip().split("\n") if result.stdout.strip() else []
        for commit in commits:
            if commit:
                total += 1
                if not check_single_patch(checker, None, commit, args.verbose, args.quiet):
                    failed += 1

    # Print summary
    passed = total - failed
    if not args.quiet:
        print(f"\n{passed}/{total} valid patch{'es' if passed != 1 else ''}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
