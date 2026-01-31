#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2015 6WIND S.A.
# Copyright 2025 - Python rewrite
#
# checkpatch.py - Check patches for common style issues
#
# This is a standalone Python replacement for the DPDK checkpatches.sh
# script that previously wrapped the Linux kernel's checkpatch.pl.

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

        # DPDK-specific ignore list (matches original shell script)
        self.ignored_types = set([
            "LINUX_VERSION_CODE", "ENOSYS", "FILE_PATH_CHANGES",
            "MAINTAINERS_STYLE", "SPDX_LICENSE_TAG", "VOLATILE",
            "PREFER_PACKED", "PREFER_ALIGNED", "PREFER_PRINTF", "STRLCPY",
            "PREFER_KERNEL_TYPES", "PREFER_FALLTHROUGH", "BIT_MACRO",
            "CONST_STRUCT", "SPLIT_STRING", "LONG_LINE_STRING",
            "C99_COMMENT_TOLERANCE", "LINE_SPACING", "PARENTHESIS_ALIGNMENT",
            "NETWORKING_BLOCK_COMMENT_STYLE", "NEW_TYPEDEFS",
            "COMPARISON_TO_NULL", "AVOID_BUG", "EXPORT_SYMBOL",
            "BAD_REPORTED_BY_LINK"
        ])

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
        if type_name.upper() in self.ignored_types:
            return

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

            prev_line = ""
            for line_num, content in lines:
                self.lines_checked += 1

                if is_c_file:
                    # Check for externs in .c files
                    if is_c_source and re.match(r"^\s*extern\b", content):
                        self.add_result(
                            "WARNING", "AVOID_EXTERNS",
                            "externs should be avoided in .c files",
                            filename, line_num, content
                        )

                    # Check for unnecessary break after goto/return/continue
                    if re.match(r"^\s*break\s*;", content):
                        if re.match(r"^\s*(goto|return|continue)\b", prev_line):
                            self.add_result(
                                "WARNING", "UNNECESSARY_BREAK",
                                "break is not useful after a goto or return",
                                filename, line_num, content
                            )

                    # Check for strncpy usage - prefer strlcpy
                    if re.search(r"\bstrncpy\s*\(", content):
                        self.add_result(
                            "WARNING", "STRNCPY",
                            "Prefer strlcpy over strncpy - see: https://lore.kernel.org/r/CAHk-=wgfRnXz0W3D37d01q3JFkr_i_uTL=V6A6G1oUZcprmknw@mail.gmail.com/",
                            filename, line_num, content
                        )

                    # Check for complex macros without proper enclosure
                    if re.match(r"^\s*#\s*define\s+\w+\s*\([^)]*\)\s+\(", content):
                        # Macro with arguments that starts with ( - check if it's a compound literal
                        if re.search(r"\)\s+\([^)]*\]\s*\)\s*\{", content) or \
                           re.search(r"\)\s+\(const\s+", content) or \
                           re.search(r"\)\s+\(enum\s+", content) or \
                           re.search(r"\)\s+\(struct\s+", content):
                            self.add_result(
                                "ERROR", "COMPLEX_MACRO",
                                "Macros with complex values should be enclosed in parentheses",
                                filename, line_num, content
                            )

                    # Check for spaces around operators
                    # if=( instead of if (
                    if re.search(r"\b(if|while|for|switch)\(", content):
                        self.add_result(
                            "WARNING", "SPACING",
                            "space required before the open parenthesis '('",
                            filename, line_num, content
                        )

                    # Check for brace placement (K&R style)
                    if re.match(r"^\s*{$", content):
                        # Opening brace on its own line (after function def is OK)
                        pass

                    # Multiple statements on one line
                    if re.search(r";\s*[a-zA-Z]", content) and "for" not in content:
                        self.add_result(
                            "CHECK", "MULTIPLE_STATEMENTS",
                            "multiple statements on one line",
                            filename, line_num, content
                        )

                    # Check for C99 comments in headers that should use C89
                    if filename.endswith(".h") and "//" in content:
                        # Only flag if not in a string
                        stripped = re.sub(r'"[^"]*"', '', content)
                        if "//" in stripped:
                            self.add_result(
                                "CHECK", "C99_COMMENTS",
                                "C99 // comments are acceptable but /* */ is preferred in headers",
                                filename, line_num, content
                            )

                prev_line = content

    def check_spelling(self, patch_info: PatchInfo) -> None:
        """Check for spelling errors using codespell dictionary."""
        if not self.spelling_dict:
            return

        for filename, lines in patch_info.added_lines.items():
            for line_num, content in lines:
                # Extract words from the line
                words = re.findall(r'\b[a-zA-Z]+\b', content)
                for word in words:
                    lower_word = word.lower()
                    if lower_word in self.spelling_dict:
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

    def check_patch(self, content: str) -> bool:
        """Run all checks on a patch."""
        self.results = []
        self.errors = 0
        self.warnings = 0
        self.checks = 0
        self.lines_checked = 0

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

        return self.errors == 0 and self.warnings == 0

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


def check_single_patch(checker: CheckPatch, patch_path: Optional[str],
                       commit: Optional[str], verbose: bool, quiet: bool) -> bool:
    """Check a single patch file or commit."""
    subject = ""
    content = ""

    if patch_path:
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

    is_clean = checker.check_patch(content)
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

    sys.exit(failed)


if __name__ == "__main__":
    main()
