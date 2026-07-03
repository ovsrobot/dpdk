#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

"""
Review DPDK patches using AI providers.

Supported providers: Anthropic Claude, OpenAI ChatGPT, xAI Grok, Google Gemini
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import date
from email.message import EmailMessage
from html import escape
from pathlib import Path
from typing import Any, Iterator

from _common import (
    PROVIDERS,
    TokenUsage,
    add_token_args,
    error,
    get_git_config,
    list_providers,
    print_token_summary,
    send_request,
)

# Output formats
OUTPUT_FORMATS = ["text", "markdown", "html", "json"]

# Large file handling modes
LARGE_FILE_MODES = ["error", "truncate", "chunk", "commits-only", "summary"]

# Approximate characters per token (conservative: fewer chars = higher estimate)
CHARS_PER_TOKEN = 3.5

# Default token limits by provider (leaving room for system prompt and response)
PROVIDER_INPUT_LIMITS = {
    "anthropic": 180000,  # 200K context, reserve for system/response
    "openai": 900000,  # GPT-4.1 has 1M context
    "xai": 1800000,  # Grok 4.1 Fast has 2M context
    "google": 900000,  # Gemini 3 Flash has 1M context
}

# LTS releases: any DPDK release with minor version .11
# (e.g., 19.11, 20.11, 21.11, 22.11, 23.11, 24.11, 25.11, ...)

SYSTEM_PROMPT_BASE = """\
You are an expert DPDK code reviewer. Analyze patches for compliance with \
DPDK coding standards and contribution guidelines. Provide clear, actionable \
feedback organized by severity (Error, Warning, Info) as defined in the \
guidelines."""

LTS_RULES = """
LTS (Long Term Stable) branch rules apply:
- Only bug fixes allowed, no new features
- No new APIs (experimental or stable)
- ABI must remain unchanged
- Backported fixes should reference the original commit with Fixes: tag
- Copyright years should reflect when the code was originally written
- Be conservative: reject changes that aren't clearly bug fixes"""

REVIEW_JSON_INSTRUCTION = """\
Respond with a single JSON object and nothing else - no markdown fences, \
no prose before or after, no section headers:
{
  "summary": "one line",
  "errors": [
    {"issue": "what is wrong", "location": "file:line",
     "evidence": "one line copied exactly from the patch",
     "suggestion": "specific fix"}
  ],
  "warnings": [same fields as errors],
  "info": [{"issue": "...", "location": "file:line", "suggestion": "..."}]
}
Rules:
- Deliberation is private. Output ONLY findings that survive your final
  checks; never output candidate findings, "Discard this item", or
  corrections.
- Empty severities are empty arrays, never prose.
- "evidence" must be copied verbatim from the patch (the added '+' line for
  new code). For missing-cleanup or missing-check findings, quote the line
  that allocates or calls. Findings whose evidence does not appear in the
  patch are discarded by the harness as unverifiable.
- If there are no findings:
  {"summary": "No issues found.", "errors": [], "warnings": [], "info": []}
"""

USER_PROMPT = """Please review the following DPDK patch file '{patch_name}' \
against the AGENTS.md guidelines. Focus on:

1. Correctness bugs (resource leaks, use-after-free, race conditions, etc.)
2. C coding style (forbidden tokens, implicit comparisons, unnecessary patterns)
3. API and documentation requirements
4. Any other guideline violations

Note: commit message formatting and SPDX/copyright compliance are checked \
by checkpatches.sh and should NOT be flagged here.

{format_instruction}

--- PATCH CONTENT ---
"""

# Exit codes for review results
EXIT_CLEAN = 0
EXIT_WARNINGS = 2
EXIT_ERRORS = 3

# Appended to the prompt when the first response was not valid JSON.
RETRY_NOTE = (
    "\n\nREMINDER: the previous response was not a single valid JSON "
    "object. Respond again with ONLY the JSON object in the required schema."
)


@dataclass
class ReviewSection:
    """One reviewed unit (whole patch file, one patch, or one chunk)."""

    label: str
    data: dict[str, Any] | None = None
    unverified: list[dict[str, Any]] = field(default_factory=list)
    raw: str | None = None

    @property
    def contract_violation(self) -> bool:
        """True when the model response could not be parsed as JSON."""
        return self.data is None


def extract_json(text: str) -> dict[str, Any] | None:
    """Parse a JSON object from model output, tolerating code fences."""
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```[a-zA-Z]*\n", "", candidate)
        candidate = re.sub(r"\n```\s*$", "", candidate)
    try:
        data = json.loads(candidate)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    # Fall back to the outermost braces
    first = candidate.find("{")
    last = candidate.rfind("}")
    if first != -1 and last > first:
        try:
            data = json.loads(candidate[first : last + 1])
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
    return None


def get_patch_ids(patch_content: str) -> list[str]:
    """Return stable patch ids for the content under review.

    Uses `git patch-id --stable`, which is invariant to format-patch
    regeneration (timestamps, commit hashes, version prefixes) but changes
    whenever the diff content changes. This pins a review to the exact
    revision it reviewed. Returns an empty list if git is unavailable.
    """
    try:
        result = subprocess.run(
            ["git", "patch-id", "--stable"],
            input=patch_content,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    ids = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if fields:
            ids.append(fields[0])
    return ids


def _normalize_line(line: str) -> str:
    """Collapse whitespace; drop a leading diff marker if present."""
    if line[:1] in "+- ":
        line = line[1:]
    return " ".join(line.split())


def build_patch_line_index(patch_content: str) -> set[str]:
    """Set of normalized lines appearing in the patch."""
    index = set()
    for line in patch_content.splitlines():
        norm = _normalize_line(line)
        if norm:
            index.add(norm)
    return index


def finding_is_verified(
    finding: dict[str, Any], line_index: set[str], patch_content: str
) -> bool:
    """Check a finding's evidence and location against the patch content.

    Guards against stale reviews (findings quoted from a different revision
    of the patch) and hallucinated line references: every evidence line must
    appear in the patch, and the file named in location must be part of it.
    """
    evidence = str(finding.get("evidence", "")).strip()
    if not evidence:
        return False
    for line in evidence.splitlines():
        norm = _normalize_line(line)
        if norm and norm not in line_index:
            return False
    location = str(finding.get("location", ""))
    fname = location.rsplit(":", 1)[0].strip()
    if fname:
        # Lenient: the model may shorten the path, so match the basename
        base = fname.rsplit("/", 1)[-1]
        if base and base not in patch_content:
            return False
    return True


def verify_findings(
    data: dict[str, Any], patch_content: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Split errors/warnings into verified and unverified findings.

    Info findings pass through unchecked; they are often general
    suggestions with no specific line to quote.
    """
    line_index = build_patch_line_index(patch_content)
    unverified = []
    verified = dict(data)
    for severity in ("errors", "warnings"):
        kept = []
        for finding in data.get(severity) or []:
            if not isinstance(finding, dict):
                continue
            if finding_is_verified(finding, line_index, patch_content):
                kept.append(finding)
            else:
                dropped = dict(finding)
                dropped["severity"] = severity[:-1]
                unverified.append(dropped)
        verified[severity] = kept
    verified["info"] = [f for f in (data.get("info") or []) if isinstance(f, dict)]
    return verified, unverified


def process_review_text(
    review_text: str, patch_content: str, label: str
) -> ReviewSection:
    """Parse and verify one model response into a ReviewSection."""
    data = extract_json(review_text)
    if data is None:
        return ReviewSection(label=label, raw=review_text)
    verified, unverified = verify_findings(data, patch_content)
    return ReviewSection(label=label, data=verified, unverified=unverified)


def section_counts(sections: list[ReviewSection]) -> dict[str, int]:
    """Aggregate finding counts across sections."""
    counts = {
        "errors": 0,
        "warnings": 0,
        "info": 0,
        "unverified": 0,
        "violations": 0,
    }
    for sec in sections:
        if sec.contract_violation:
            counts["violations"] += 1
            continue
        counts["errors"] += len(sec.data.get("errors", []))
        counts["warnings"] += len(sec.data.get("warnings", []))
        counts["info"] += len(sec.data.get("info", []))
        counts["unverified"] += len(sec.unverified)
    return counts


def classify_review(counts: dict[str, int]) -> int:
    """Exit code from verified finding counts.

    Status is derived ONLY from the parsed, verified findings - never from
    pattern matching on prose (a "### Errors" header above "None found"
    must not trip the classifier).

    Returns:
        0 - clean (no errors or warnings)
        2 - warnings, unverified findings, or output-contract violations
        3 - errors found
    """
    if counts["errors"]:
        return EXIT_ERRORS
    if counts["warnings"] or counts["unverified"] or counts["violations"]:
        return EXIT_WARNINGS
    return EXIT_CLEAN


def summary_trailer(counts: dict[str, int], patch_ids: list[str]) -> str:
    """One-line machine-readable verdict for CI to parse.

    CI labelers should parse this line (or the JSON output), not the prose.
    """
    ids = ",".join(pid[:16] for pid in patch_ids) or "unknown"
    return (
        f"X-AI-Review: errors={counts['errors']} "
        f"warnings={counts['warnings']} info={counts['info']} "
        f"unverified={counts['unverified']} "
        f"contract-violations={counts['violations']} patch-id={ids}"
    )


def is_lts_release(release: str | None) -> bool:
    """Check if a release is an LTS release.

    Per DPDK project guidelines, any release with minor version .11
    is an LTS release (e.g., 19.11, 21.11, 23.11, 24.11, 25.11).
    """
    if not release:
        return False
    # Check for explicit -lts suffix
    if "-lts" in release.lower():
        return True
    # Extract base version (e.g., "23.11" from "23.11.1" or "23.11-rc1")
    version = release.split("-")[0]
    parts = version.split(".")
    if len(parts) >= 2:
        try:
            minor = int(parts[1])
            return minor == 11
        except ValueError:
            pass
    return False


def estimate_tokens(text: str) -> int:
    """Estimate token count from text length."""
    return int(len(text) / CHARS_PER_TOKEN)


def split_mbox_patches(content: str) -> list[str]:
    """Split an mbox file into individual patches."""
    patches = []
    current_patch = []
    in_patch = False

    for line in content.split("\n"):
        # Detect start of new message in mbox format
        # git-format-patch: "From <40-char-hex> Mon Sep 17 00:00:00 2001"
        # general mbox: "From <addr> <day-of-week> ..."
        if line.startswith("From ") and (
            re.match(r"^From [0-9a-f]{40} ", line)
            or " Mon " in line
            or " Tue " in line
            or " Wed " in line
            or " Thu " in line
            or " Fri " in line
            or " Sat " in line
            or " Sun " in line
        ):
            if current_patch:
                patches.append("\n".join(current_patch))
            current_patch = [line]
            in_patch = True
        elif in_patch:
            current_patch.append(line)

    # Don't forget the last patch
    if current_patch:
        patches.append("\n".join(current_patch))

    return patches if patches else [content]


def extract_commit_messages(content: str) -> str:
    """Extract only commit messages from patch content."""
    patches = split_mbox_patches(content)
    messages = []

    for patch in patches:
        lines = patch.split("\n")
        msg_lines = []
        in_headers = True
        in_body = False
        found_subject = False

        for line in lines:
            # Collect headers we care about
            if in_headers:
                if line.startswith("Subject:"):
                    msg_lines.append(line)
                    found_subject = True
                elif line.startswith(("From:", "Date:")):
                    msg_lines.append(line)
                elif line.startswith((" ", "\t")) and found_subject:
                    # Subject continuation
                    msg_lines.append(line)
                elif line == "":
                    if found_subject:
                        in_headers = False
                        in_body = True
                        msg_lines.append("")
            elif in_body:
                # Stop at the diffstat separator or diff
                if line.rstrip() == "---":
                    break
                if line.startswith("diff --git"):
                    break
                msg_lines.append(line)

        if msg_lines:
            messages.append("\n".join(msg_lines))

    return "\n\n---\n\n".join(messages)


def truncate_content(content: str, max_tokens: float) -> tuple[str, bool]:
    """Truncate content to fit within token limit."""
    max_chars = int(max_tokens * CHARS_PER_TOKEN)

    if len(content) <= max_chars:
        return content, False

    # Try to truncate at a reasonable boundary
    truncated = content[:max_chars]

    # Find last complete diff hunk or patch boundary
    last_diff = truncated.rfind("\ndiff --git")
    last_patch = truncated.rfind("\nFrom ")

    if last_diff > max_chars * 0.5:
        truncated = truncated[:last_diff]
    elif last_patch > max_chars * 0.5:
        truncated = truncated[:last_patch]

    truncated += "\n\n[... Content truncated due to size limits ...]\n"
    return truncated, True


def chunk_content(content: str, max_tokens: int) -> Iterator[tuple[str, int, int]]:
    """Split content into chunks that fit within token limit.

    Yields tuples of (chunk_content, chunk_number, total_chunks).
    """
    patches = split_mbox_patches(content)

    if len(patches) == 1:
        # Single large patch - split by diff sections
        yield from chunk_single_patch(content, max_tokens)
        return

    # Multiple patches - group them to fit within limits
    chunks = []
    current_chunk = []
    current_size = 0
    max_chars = int(max_tokens * CHARS_PER_TOKEN * 0.9)  # 90% to leave margin

    for patch in patches:
        patch_size = len(patch)
        if current_size + patch_size > max_chars and current_chunk:
            chunks.append("\n".join(current_chunk))
            current_chunk = []
            current_size = 0

        if patch_size > max_chars:
            # Single patch too large, truncate it
            if current_chunk:
                chunks.append("\n".join(current_chunk))
                current_chunk = []
                current_size = 0
            truncated, _ = truncate_content(patch, max_tokens * 0.9)
            chunks.append(truncated)
        else:
            current_chunk.append(patch)
            current_size += patch_size

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    total = len(chunks)
    for i, chunk in enumerate(chunks, 1):
        yield chunk, i, total


def chunk_single_patch(content: str, max_tokens: int) -> Iterator[tuple[str, int, int]]:
    """Split a single large patch by diff sections."""
    max_chars = int(max_tokens * CHARS_PER_TOKEN * 0.9)

    # Extract header (everything before first diff)
    first_diff = content.find("\ndiff --git")
    if first_diff == -1:
        # No diff sections, just truncate
        truncated, _ = truncate_content(content, max_tokens * 0.9)
        yield truncated, 1, 1
        return

    header = content[: first_diff + 1]
    diff_content = content[first_diff + 1 :]

    # Split by diff sections
    diffs = []
    current_diff = []
    for line in diff_content.split("\n"):
        if line.startswith("diff --git") and current_diff:
            diffs.append("\n".join(current_diff))
            current_diff = []
        current_diff.append(line)
    if current_diff:
        diffs.append("\n".join(current_diff))

    # Group diffs into chunks
    chunks = []
    current_chunk_diffs = []
    current_size = len(header)

    for diff in diffs:
        diff_size = len(diff)
        if current_size + diff_size > max_chars and current_chunk_diffs:
            chunks.append(header + "\n".join(current_chunk_diffs))
            current_chunk_diffs = []
            current_size = len(header)

        if diff_size + len(header) > max_chars:
            # Single diff too large
            if current_chunk_diffs:
                chunks.append(header + "\n".join(current_chunk_diffs))
                current_chunk_diffs = []
            truncated_diff = diff[: max_chars - len(header) - 100]
            truncated_diff += "\n[... diff truncated ...]\n"
            chunks.append(header + truncated_diff)
            current_size = len(header)
        else:
            current_chunk_diffs.append(diff)
            current_size += diff_size

    if current_chunk_diffs:
        chunks.append(header + "\n".join(current_chunk_diffs))

    total = len(chunks)
    for i, chunk in enumerate(chunks, 1):
        yield chunk, i, total


def get_summary_prompt() -> str:
    """Get prompt modifications for summary mode."""
    return """
NOTE: This is a LARGE patch series. Provide a HIGH-LEVEL summary review only:
- Focus on overall architecture and design concerns
- Check commit message formatting across the series
- Identify any obvious policy violations
- Do NOT attempt detailed line-by-line code review
- Summarize the scope and purpose of the changes
"""


def _finding_lines(num: int, finding: dict[str, Any]) -> list[str]:
    """Render one finding as indented text lines."""
    lines = [f"  {num}. {finding.get('location') or 'unspecified location'}"]
    issue = str(finding.get("issue", "")).strip()
    if issue:
        lines.append(f"     {issue}")
    for ev_line in str(finding.get("evidence", "")).strip().splitlines():
        lines.append(f"     > {ev_line}")
    suggestion = str(finding.get("suggestion", "")).strip()
    if suggestion:
        lines.append(f"     Fix: {suggestion}")
    return lines


def render_section_text(sec: ReviewSection) -> str:
    """Render one ReviewSection as plain text."""
    if sec.contract_violation:
        return (
            "Output contract violation: the model response was not a valid "
            "JSON review.\nRaw response follows (unparsed, counted as a "
            f"warning):\n\n{sec.raw}"
        )
    lines: list[str] = []
    summary = str(sec.data.get("summary", "")).strip()
    if summary:
        lines.append(summary)
    titles = (("errors", "Errors"), ("warnings", "Warnings"), ("info", "Info"))
    for key, title in titles:
        findings = sec.data.get(key, [])
        if not findings:
            continue
        lines.append("")
        lines.append(f"{title}:")
        for i, finding in enumerate(findings, 1):
            lines.extend(_finding_lines(i, finding))
    if sec.unverified:
        lines.append("")
        lines.append(
            "Unverified findings (evidence not found in this patch "
            "revision; possibly from a stale review - not counted):"
        )
        for i, finding in enumerate(sec.unverified, 1):
            lines.extend(_finding_lines(i, finding))
    if len(lines) <= 1 and not sec.unverified:
        return summary or "No issues found."
    return "\n".join(lines)


def render_sections(sections: list[ReviewSection], output_format: str) -> str:
    """Render all sections in the requested format.

    Markdown and HTML are simple wrappings of the text rendering; findings
    content comes from the verified structure in all formats.
    """
    parts = []
    for sec in sections:
        body = render_section_text(sec)
        if output_format == "markdown":
            if len(sections) > 1:
                parts.append(f"## {sec.label}\n\n```\n{body}\n```")
            else:
                parts.append(f"```\n{body}\n```")
        elif output_format == "html":
            title = f"<h2>{escape(sec.label)}</h2>\n" if len(sections) > 1 else ""
            parts.append(f"{title}<pre>{escape(body)}</pre>")
        else:  # text
            if len(sections) > 1:
                parts.append(f"=== {sec.label} ===\n\n{body}")
            else:
                parts.append(body)
    if output_format == "markdown":
        return "\n\n---\n\n".join(parts)
    if output_format == "html":
        return "\n<hr>\n".join(parts)
    separator = "\n\n" + "=" * 60 + "\n\n"
    return separator.join(parts)


def build_system_prompt(review_date: str, release: str | None) -> str:
    """Build system prompt with date and release context."""
    prompt = SYSTEM_PROMPT_BASE
    prompt += f"\n\nCurrent date: {review_date}."

    if release:
        prompt += f"\nTarget DPDK release: {release}."
        if is_lts_release(release):
            prompt += LTS_RULES
        else:
            prompt += "\nThis is a main branch or standard release."
            prompt += "\nNew features and experimental APIs are allowed."

    return prompt


def build_anthropic_request(
    model: str,
    max_tokens: int,
    system_prompt: str,
    agents_content: str,
    patch_content: str,
    patch_name: str,
    retry_note: str = "",
) -> dict[str, Any]:
    """Build request payload for Anthropic API."""
    format_instruction = REVIEW_JSON_INSTRUCTION + retry_note
    user_prompt = USER_PROMPT.format(
        patch_name=patch_name, format_instruction=format_instruction
    )
    return {
        "model": model,
        "max_tokens": max_tokens,
        "system": [
            {"type": "text", "text": system_prompt},
            {
                "type": "text",
                "text": agents_content,
                "cache_control": {"type": "ephemeral"},
            },
        ],
        "messages": [
            {
                "role": "user",
                "content": user_prompt + patch_content,
            }
        ],
    }


def build_openai_request(
    model: str,
    max_tokens: int,
    system_prompt: str,
    agents_content: str,
    patch_content: str,
    patch_name: str,
    retry_note: str = "",
) -> dict[str, Any]:
    """Build request payload for OpenAI-compatible APIs."""
    format_instruction = REVIEW_JSON_INSTRUCTION + retry_note
    user_prompt = USER_PROMPT.format(
        patch_name=patch_name, format_instruction=format_instruction
    )
    return {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "system", "content": agents_content},
            {
                "role": "user",
                "content": user_prompt + patch_content,
            },
        ],
    }


def build_google_request(
    max_tokens: int,
    system_prompt: str,
    agents_content: str,
    patch_content: str,
    patch_name: str,
    retry_note: str = "",
) -> dict[str, Any]:
    """Build request payload for Google Gemini API."""
    format_instruction = REVIEW_JSON_INSTRUCTION + retry_note
    user_prompt = USER_PROMPT.format(
        patch_name=patch_name, format_instruction=format_instruction
    )
    return {
        "systemInstruction": {
            "parts": [
                {"text": system_prompt},
                {"text": agents_content},
            ]
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": user_prompt + patch_content}],
            },
        ],
        "generationConfig": {"maxOutputTokens": max_tokens},
    }


def call_api(
    provider: str,
    api_key: str,
    model: str,
    max_tokens: int,
    system_prompt: str,
    agents_content: str,
    patch_content: str,
    patch_name: str,
    retry_note: str = "",
    verbose: bool = False,
    timeout: int = 300,
) -> tuple[str, TokenUsage]:
    """Build the per-provider request body and dispatch via _common."""
    if provider == "anthropic":
        request_data = build_anthropic_request(
            model,
            max_tokens,
            system_prompt,
            agents_content,
            patch_content,
            patch_name,
            retry_note,
        )
    elif provider == "google":
        request_data = build_google_request(
            max_tokens,
            system_prompt,
            agents_content,
            patch_content,
            patch_name,
            retry_note,
        )
    else:  # openai, xai
        request_data = build_openai_request(
            model,
            max_tokens,
            system_prompt,
            agents_content,
            patch_content,
            patch_name,
            retry_note,
        )
    return send_request(
        provider,
        api_key,
        model,
        request_data,
        timeout=timeout,
        verbose=verbose,
    )


def reviewed_section(
    provider: str,
    api_key: str,
    model: str,
    max_tokens: int,
    system_prompt: str,
    agents_content: str,
    content: str,
    name: str,
    label: str,
    verbose: bool,
    timeout: int,
    usage: TokenUsage,
) -> ReviewSection:
    """Run one review call, retrying once if the response is not valid JSON."""
    review_text, call_usage = call_api(
        provider,
        api_key,
        model,
        max_tokens,
        system_prompt,
        agents_content,
        content,
        name,
        "",
        verbose,
        timeout,
    )
    usage.add(call_usage)
    section = process_review_text(review_text, content, label)
    if section.contract_violation:
        print(
            f"{label}: response was not valid JSON, retrying once...",
            file=sys.stderr,
        )
        review_text, call_usage = call_api(
            provider,
            api_key,
            model,
            max_tokens,
            system_prompt,
            agents_content,
            content,
            name,
            RETRY_NOTE,
            verbose,
            timeout,
        )
        usage.add(call_usage)
        section = process_review_text(review_text, content, label)
    return section


def get_last_message_id(patch_content: str) -> str | None:
    """Extract Message-ID from the last patch in an mbox."""
    msg_ids = re.findall(
        r"^Message-I[Dd]:\s*(.+)$", patch_content, re.MULTILINE | re.IGNORECASE
    )
    if msg_ids:
        msg_id = msg_ids[-1].strip()
        # Normalize: remove < > and add them back
        msg_id = msg_id.strip("<>")
        return f"<{msg_id}>"
    return None


def get_last_subject(patch_content: str) -> str | None:
    """Extract subject from the last patch in an mbox."""
    # Find all Subject lines with potential continuations
    subjects = []
    lines = patch_content.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].lower().startswith("subject:"):
            subject = lines[i][8:].strip()
            i += 1
            # Handle continuation lines (RFC 2822 folding)
            while i < len(lines) and lines[i].startswith((" ", "\t")):
                subject += " " + lines[i].strip()
                i += 1
            subjects.append(subject)
        else:
            i += 1
    return subjects[-1] if subjects else None


def send_email(
    to_addrs: list[str],
    cc_addrs: list[str],
    from_addr: str,
    subject: str,
    in_reply_to: str | None,
    body: str,
    dry_run: bool = False,
) -> bool:
    """Send review email using git send-email, sendmail, or msmtp.

    TODO: This duplicates send_email in review-doc.py, which uses direct
    smtplib with git sendemail.* config instead of shelling out. Both
    approaches work; pick one and move it to _common.py.
    """
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    msg["Subject"] = subject
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = in_reply_to
    msg.set_content(body)

    email_text = msg.as_string()

    if dry_run:
        print("=== Email Preview (dry-run) ===", file=sys.stderr)
        print(email_text, file=sys.stderr)
        print("=== End Preview ===", file=sys.stderr)
        return True

    # Write to temp file for git send-email
    with tempfile.NamedTemporaryFile(mode="w", suffix=".eml", delete=False) as f:
        f.write(email_text)
        temp_file = f.name

    try:
        # Try git send-email first
        if get_git_config("sendemail.smtpserver"):
            # Build command with all arguments
            flat_cmd = ["git", "send-email", "--confirm=never", "--quiet"]
            for addr in to_addrs:
                flat_cmd.extend(["--to", addr])
            for addr in cc_addrs:
                flat_cmd.extend(["--cc", addr])
            if from_addr:
                flat_cmd.extend(["--from", from_addr])
            if in_reply_to:
                flat_cmd.extend(["--in-reply-to", in_reply_to])
            flat_cmd.append(temp_file)

            try:
                subprocess.run(flat_cmd, check=True, capture_output=True)
                print("Email sent via git send-email", file=sys.stderr)
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

        # Try sendmail
        try:
            subprocess.run(
                ["sendmail", "-t"],
                input=email_text,
                text=True,
                capture_output=True,
                check=True,
            )
            print("Email sent via sendmail", file=sys.stderr)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        # Try msmtp
        try:
            subprocess.run(
                ["msmtp", "-t"],
                input=email_text,
                text=True,
                capture_output=True,
                check=True,
            )
            print("Email sent via msmtp", file=sys.stderr)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        error("Could not send email. Configure git send-email, sendmail, or msmtp.")

    finally:
        os.unlink(temp_file)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Review DPDK patches using AI providers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s patch.patch                    # Review with default settings
    %(prog)s -p openai my-patch.patch       # Use OpenAI ChatGPT
    %(prog)s -f markdown patch.patch        # Output as Markdown
    %(prog)s -f json -o review.json patch.patch  # Save JSON to file
    %(prog)s -f html -o review.html patch.patch  # Save HTML to file
    %(prog)s -r 24.11 patch.patch           # Review for specific release
    %(prog)s -r 24.11-lts patch.patch       # Review for LTS branch
    %(prog)s --send-email --to dev@dpdk.org series.mbox
    %(prog)s --send-email --to dev@dpdk.org --dry-run series.mbox

Large File Handling:
    %(prog)s --split-patches series.mbox    # Review each patch separately
    %(prog)s --split-patches --patch-range 1-5 series.mbox  # Review patches 1-5
    %(prog)s --large-file=truncate patch.mbox   # Truncate to fit limit
    %(prog)s --large-file=commits-only series.mbox  # Review commit messages only
    %(prog)s --large-file=summary series.mbox   # High-level summary only
    %(prog)s --large-file=chunk series.mbox     # Split and review in chunks

Large File Modes:
    error       - Fail with error (default)
    truncate    - Truncate content to fit token limit
    chunk       - Split into chunks and review each
    commits-only - Extract and review only commit messages
    summary     - Request high-level summary review

LTS Releases:
    Use -r/--release with LTS version (e.g., 24.11-lts, 23.11) to enable
    stricter review rules: bug fixes only, no new features or APIs.
    Any DPDK release with minor version .11 is an LTS release.

Token Usage:
    Use --show-tokens (or -v/--verbose) to print a token usage summary
    on stderr after the run. Off by default.

Review Integrity:
    The model must return structured JSON findings; text/markdown/html are
    rendered locally from the verified findings. Each error/warning must
    quote an exact line from the patch as evidence; findings whose evidence
    is not present in the patch (e.g. review of a stale revision) are
    reported as unverified and do not affect the error count. Every output
    carries the `git patch-id --stable` of the reviewed content and a final
    "X-AI-Review: ..." verdict line for CI to parse.

Testing:
    %(prog)s --replay saved-response.txt patch.patch   # no API call

Exit Codes:
    0 - Clean review (no errors or warnings)
    1 - Operational failure (missing API key, file not found, etc.)
    2 - Review found warnings, unverified findings, or the model violated
        the output contract (no errors)
    3 - Review found errors
        """,
    )

    parser.add_argument("patch_file", nargs="?", help="Patch file to review")
    parser.add_argument(
        "-p",
        "--provider",
        choices=PROVIDERS.keys(),
        default="anthropic",
        help="AI provider (default: anthropic)",
    )
    parser.add_argument(
        "-a",
        "--agents",
        default="AGENTS.md",
        help="Path to AGENTS.md file (default: AGENTS.md)",
    )
    parser.add_argument(
        "-m",
        "--model",
        help="Model to use (default: provider-specific)",
    )
    parser.add_argument(
        "-t",
        "--tokens",
        type=int,
        default=4096,
        help="Max tokens for response (default: 4096)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show API request details",
    )
    add_token_args(parser)
    parser.add_argument(
        "-f",
        "--format",
        choices=OUTPUT_FORMATS,
        default="text",
        dest="output_format",
        help="Output format: text, markdown, html, json (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "-l",
        "--list-providers",
        action="store_true",
        help="List available providers and exit",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        metavar="SECONDS",
        help="API request timeout in seconds (default: 300)",
    )
    parser.add_argument(
        "--replay",
        metavar="FILE",
        help="Testing aid: process a saved model response instead of "
        "calling the API (reviews the patch file as a single unit)",
    )

    # Date and release options
    parser.add_argument(
        "-D",
        "--date",
        metavar="YYYY-MM-DD",
        help="Review date context (default: today)",
    )
    parser.add_argument(
        "-r",
        "--release",
        metavar="VERSION",
        help="Target DPDK release (e.g., 24.11, 23.11-lts)",
    )

    # Large file handling options
    large_group = parser.add_argument_group("Large File Handling")
    large_group.add_argument(
        "--large-file",
        choices=LARGE_FILE_MODES,
        default="error",
        metavar="MODE",
        help="How to handle large files: error (default), truncate, "
        "chunk, commits-only, summary",
    )
    large_group.add_argument(
        "--max-tokens",
        type=int,
        metavar="N",
        help="Max input tokens (default: provider-specific)",
    )
    large_group.add_argument(
        "--split-patches",
        action="store_true",
        help="Split mbox into individual patches and review each separately",
    )
    large_group.add_argument(
        "--patch-range",
        metavar="N-M",
        help="Review only patches N through M (1-indexed, use with --split-patches)",
    )

    # Email options
    email_group = parser.add_argument_group("Email Options")
    email_group.add_argument(
        "--send-email",
        action="store_true",
        help="Send review via email",
    )
    email_group.add_argument(
        "--to",
        action="append",
        dest="to_addrs",
        default=[],
        metavar="ADDRESS",
        help="Email recipient (can be specified multiple times)",
    )
    email_group.add_argument(
        "--cc",
        action="append",
        dest="cc_addrs",
        default=[],
        metavar="ADDRESS",
        help="CC recipient (can be specified multiple times)",
    )
    email_group.add_argument(
        "--from",
        dest="from_addr",
        metavar="ADDRESS",
        help="From address (default: from git config)",
    )
    email_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Show email without sending",
    )

    args = parser.parse_args()

    if args.list_providers:
        list_providers()

    # Check patch file is provided
    if not args.patch_file:
        parser.error("patch_file is required")

    # Get provider config
    config = PROVIDERS[args.provider]
    model = args.model or config["default_model"]

    # Get API key (not needed when replaying a saved response)
    api_key = os.environ.get(config["env_var"], "")
    if not api_key and not args.replay:
        error(f"{config['env_var']} environment variable not set")

    # Validate files
    agents_path = Path(args.agents)
    if not agents_path.exists():
        error(f"AGENTS.md not found: {args.agents}")

    patch_path = Path(args.patch_file)
    if not patch_path.exists():
        error(f"Patch file not found: {args.patch_file}")

    # Validate email options
    if args.send_email and not args.to_addrs:
        error("--send-email requires at least one --to address")

    # Get from address for email
    from_addr = args.from_addr
    if args.send_email and not from_addr:
        git_name = get_git_config("user.name")
        git_email = get_git_config("user.email")
        if git_email:
            from_addr = f"{git_name} <{git_email}>" if git_name else git_email
        else:
            error("No --from specified and git user.email not configured")

    # Determine review date
    review_date = args.date or date.today().isoformat()

    # Build system prompt with date and release context
    system_prompt = build_system_prompt(review_date, args.release)

    # Read files
    # Files may have non-UTF-8 bytes (binary patches, unusual filenames); replace
    # rather than crashing so the review can still run.
    agents_content = agents_path.read_text(encoding="utf-8", errors="replace")
    patch_content = patch_path.read_text(encoding="utf-8", errors="replace")
    patch_name = patch_path.name

    # Determine max tokens for this provider
    max_input_tokens = args.max_tokens or PROVIDER_INPUT_LIMITS.get(
        args.provider, 100000
    )

    # Estimate token count
    estimated_tokens = estimate_tokens(patch_content + agents_content)

    # Accumulate token usage across all API calls
    total_usage = TokenUsage()

    # Parse patch range if specified
    patch_start, patch_end = None, None
    if args.patch_range:
        try:
            if "-" in args.patch_range:
                start, end = args.patch_range.split("-", 1)
                patch_start = int(start)
                patch_end = int(end)
            else:
                patch_start = patch_end = int(args.patch_range)
        except ValueError:
            error(f"Invalid --patch-range format: {args.patch_range}")
        if not args.split_patches:
            print(
                "Warning: --patch-range has no effect without --split-patches",
                file=sys.stderr,
            )

    # Reviewed sections accumulate here in all modes
    sections: list[ReviewSection] = []

    # Handle --split-patches mode
    if args.split_patches and not args.replay:
        patches = split_mbox_patches(patch_content)
        total_patches = len(patches)

        if total_patches == 1:
            print(
                "Note: Only 1 patch found in mbox, --split-patches has no effect",
                file=sys.stderr,
            )
        else:
            print(
                f"Found {total_patches} patches in mbox",
                file=sys.stderr,
            )

            # Apply patch range filter
            if patch_start is not None:
                if patch_start < 1 or patch_start > total_patches:
                    error(
                        f"Patch range start {patch_start} out of range (1-{total_patches})"
                    )
                if patch_end < patch_start or patch_end > total_patches:
                    error(
                        f"Patch range end {patch_end} out of range ({patch_start}-{total_patches})"
                    )
                patches = patches[patch_start - 1 : patch_end]
                print(
                    f"Reviewing patches {patch_start}-{patch_end} ({len(patches)} patches)",
                    file=sys.stderr,
                )

            # Review each patch separately
            for i, patch in enumerate(patches, patch_start or 1):
                patch_label = f"Patch {i}/{total_patches}"
                print(f"\nReviewing {patch_label}...", file=sys.stderr)

                sections.append(
                    reviewed_section(
                        args.provider,
                        api_key,
                        model,
                        args.tokens,
                        system_prompt,
                        agents_content,
                        patch,
                        f"{patch_name} ({patch_label})",
                        patch_label,
                        args.verbose,
                        args.timeout,
                        total_usage,
                    )
                )

            # Skip the normal API call
            estimated_tokens = 0  # Bypass size check since we've already processed

    # Check if content is too large (replay skips API size limits)
    is_large = estimated_tokens > max_input_tokens and not args.replay

    if is_large:
        print(
            f"Warning: Estimated {estimated_tokens:,} tokens exceeds limit of "
            f"{max_input_tokens:,}",
            file=sys.stderr,
        )

        if args.large_file == "error":
            error(
                f"Patch file too large ({estimated_tokens:,} tokens). "
                f"Use --large-file=truncate|chunk|commits-only|summary to handle, "
                f"or --split-patches to review patches individually."
            )
        elif args.large_file == "truncate":
            print("Truncating content to fit token limit...", file=sys.stderr)
            patch_content, was_truncated = truncate_content(
                patch_content, max_input_tokens
            )
            if was_truncated:
                print("Content was truncated.", file=sys.stderr)
        elif args.large_file == "commits-only":
            print("Extracting commit messages only...", file=sys.stderr)
            patch_content = extract_commit_messages(patch_content)
            new_estimate = estimate_tokens(patch_content + agents_content)
            print(
                f"Reduced to ~{new_estimate:,} tokens (commit messages only)",
                file=sys.stderr,
            )
            if new_estimate > max_input_tokens:
                patch_content, _ = truncate_content(patch_content, max_input_tokens)
        elif args.large_file == "summary":
            print("Using summary mode for large patch...", file=sys.stderr)
            system_prompt += get_summary_prompt()
            patch_content, _ = truncate_content(patch_content, max_input_tokens)
        elif args.large_file == "chunk":
            print("Processing in chunks...", file=sys.stderr)
            for chunk, chunk_num, total_chunks in chunk_content(
                patch_content, max_input_tokens
            ):
                chunk_label = f"Chunk {chunk_num}/{total_chunks}"
                print(f"Reviewing {chunk_label}...", file=sys.stderr)

                sections.append(
                    reviewed_section(
                        args.provider,
                        api_key,
                        model,
                        args.tokens,
                        system_prompt,
                        agents_content,
                        chunk,
                        f"{patch_name} ({chunk_label})",
                        chunk_label,
                        args.verbose,
                        args.timeout,
                        total_usage,
                    )
                )

            # Skip the normal single API call below
            estimated_tokens = 0

    if args.verbose:
        print("=== Request ===", file=sys.stderr)
        print(f"Provider: {args.provider}", file=sys.stderr)
        print(f"Model: {model}", file=sys.stderr)
        print(f"Review date: {review_date}", file=sys.stderr)
        if args.release:
            lts_status = " (LTS)" if is_lts_release(args.release) else ""
            print(f"Target release: {args.release}{lts_status}", file=sys.stderr)
        print(f"Output format: {args.output_format}", file=sys.stderr)
        print(f"AGENTS file: {args.agents}", file=sys.stderr)
        print(f"Patch file: {args.patch_file}", file=sys.stderr)
        print(f"Estimated tokens: {estimated_tokens:,}", file=sys.stderr)
        print(f"Max input tokens: {max_input_tokens:,}", file=sys.stderr)
        if args.large_file != "error":
            print(f"Large file mode: {args.large_file}", file=sys.stderr)
        if args.split_patches:
            print("Split patches: yes", file=sys.stderr)
        if args.output:
            print(f"Output file: {args.output}", file=sys.stderr)
        if args.send_email:
            print("Send email: yes", file=sys.stderr)
            print(f"To: {', '.join(args.to_addrs)}", file=sys.stderr)
            if args.cc_addrs:
                print(f"Cc: {', '.join(args.cc_addrs)}", file=sys.stderr)
            print(f"From: {from_addr}", file=sys.stderr)
        print("===============", file=sys.stderr)

    # Review the whole file (unless already processed via chunks/split)
    if args.replay:
        replay_path = Path(args.replay)
        if not replay_path.exists():
            error(f"Replay file not found: {args.replay}")
        review_text = replay_path.read_text(encoding="utf-8", errors="replace")
        sections = [process_review_text(review_text, patch_content, patch_name)]
    elif not sections:
        sections.append(
            reviewed_section(
                args.provider,
                api_key,
                model,
                args.tokens,
                system_prompt,
                agents_content,
                patch_content,
                patch_name,
                patch_name,
                args.verbose,
                args.timeout,
                total_usage,
            )
        )

    if not sections:
        error(f"No response received from {args.provider}")

    # Verify identity of the reviewed content and derive the verdict
    patch_ids = get_patch_ids(patch_content)
    counts = section_counts(sections)
    trailer = summary_trailer(counts, patch_ids)
    review_body = render_sections(sections, args.output_format)

    # Format output based on requested format
    provider_name = config["name"]
    patch_id_label = ",".join(pid[:16] for pid in patch_ids) or "unknown"

    if args.output_format == "json":
        usage_data = {
            "api_calls": total_usage.api_calls,
            "input_tokens": total_usage.input_tokens,
            "output_tokens": total_usage.output_tokens,
            "total_tokens": total_usage.input_tokens + total_usage.output_tokens,
        }
        if total_usage.cache_creation_tokens:
            usage_data["cache_creation_tokens"] = total_usage.cache_creation_tokens
        if total_usage.cache_read_tokens:
            usage_data["cache_read_tokens"] = total_usage.cache_read_tokens

        output_data = {
            "metadata": {
                "patch_file": patch_name,
                "patch_ids": patch_ids,
                "provider": args.provider,
                "provider_name": provider_name,
                "model": model,
                "review_date": review_date,
                "target_release": args.release,
                "is_lts": is_lts_release(args.release) if args.release else False,
                "counts": counts,
                "token_usage": usage_data,
            },
            "sections": [
                {
                    "label": sec.label,
                    "contract_violation": sec.contract_violation,
                    "review": sec.data,
                    "unverified_findings": sec.unverified,
                    **({"raw_response": sec.raw} if sec.raw else {}),
                }
                for sec in sections
            ],
        }
        output_text = json.dumps(output_data, indent=2)
    elif args.output_format == "html":
        release_info = ""
        if args.release:
            lts_badge = " (LTS)" if is_lts_release(args.release) else ""
            release_info = f"<br>Target release: {args.release}{lts_badge}"
        output_text = f"""<!-- AI-generated review of {patch_name} -->
<!-- Reviewed using {provider_name} ({model}) on {review_date} -->
<div class="patch-review">
<h1>Patch Review: {patch_name}</h1>
<p class="review-meta">Reviewed by {provider_name} ({model}) on {review_date}{release_info}<br>Patch-Id: {patch_id_label}</p>
{review_body}
<p class="review-verdict">{escape(trailer)}</p>
</div>
"""
    elif args.output_format == "markdown":
        release_info = ""
        if args.release:
            lts_badge = " (LTS)" if is_lts_release(args.release) else ""
            release_info = f"\n*Target release: {args.release}{lts_badge}*\n"
        output_text = f"""# Patch Review: {patch_name}

*Reviewed by {provider_name} ({model}) on {review_date}*
*Patch-Id: {patch_id_label}*
{release_info}
{review_body}

{trailer}
"""
    else:  # text
        release_info = ""
        if args.release:
            lts_badge = " (LTS)" if is_lts_release(args.release) else ""
            release_info = f"Target release: {args.release}{lts_badge}\n"
        output_text = f"=== Patch Review: {patch_name} (via {provider_name}) ===\n"
        output_text += f"Review date: {review_date}\n"
        output_text += f"Patch-Id: {patch_id_label}\n"
        output_text += release_info
        output_text += "\n" + review_body
        output_text += "\n\n" + trailer + "\n"

    # Write output
    if args.output:
        Path(args.output).write_text(output_text)
        print(f"Review written to: {args.output}", file=sys.stderr)
    else:
        print(output_text)

    print_token_summary(
        total_usage,
        args.provider,
        model,
        args.show_tokens or args.verbose,
    )

    # Send email if requested
    if args.send_email:
        # Email always uses plain text - warn if different format requested
        if args.output_format != "text":
            print(
                f"Note: Email will be sent as plain text regardless of "
                f"--format={args.output_format}",
                file=sys.stderr,
            )

        in_reply_to = get_last_message_id(patch_content)
        orig_subject = get_last_subject(patch_content)

        if orig_subject:
            # Remove [PATCH n/m] prefix
            review_subject = re.sub(r"^\[PATCH[^\]]*\]\s*", "", orig_subject)
            review_subject = f"[REVIEW] {review_subject}"
        else:
            review_subject = f"[REVIEW] {patch_name}"

        # Build email body - always use plain text version
        release_info = ""
        if args.release:
            lts_badge = " (LTS)" if is_lts_release(args.release) else ""
            release_info = f"Target release: {args.release}{lts_badge}\n"

        email_body = f"""AI-generated review of {patch_name}
Reviewed using {provider_name} ({model}) on {review_date}
Patch-Id: {patch_id_label}
{release_info}
This is an automated review. Please verify all suggestions.

---

{render_sections(sections, "text")}

{trailer}
"""

        if args.verbose:
            print("", file=sys.stderr)
            print("=== Email Details ===", file=sys.stderr)
            print(f"Subject: {review_subject}", file=sys.stderr)
            print(f"In-Reply-To: {in_reply_to}", file=sys.stderr)
            print("=====================", file=sys.stderr)

        send_email(
            args.to_addrs,
            args.cc_addrs,
            from_addr,
            review_subject,
            in_reply_to,
            email_body,
            args.dry_run,
        )

        if not args.dry_run:
            print("", file=sys.stderr)
            print(f"Review sent to: {', '.join(args.to_addrs)}", file=sys.stderr)

    # Exit with code based on verified review severity
    sys.exit(classify_review(counts))


if __name__ == "__main__":
    main()
