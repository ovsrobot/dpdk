#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

"""
Review DPDK documentation files using AI providers.

Produces a diff file and commit message compliant with DPDK standards.
Accepts multiple documentation files and generates output for each.
Supported providers: Anthropic Claude, OpenAI ChatGPT, xAI Grok, Google Gemini
"""

import argparse
import getpass
import json
import os
import re
import smtplib
import ssl
import subprocess
import sys
from email.message import EmailMessage
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Output formats
OUTPUT_FORMATS = ["text", "markdown", "html", "json"]

# Map output format to file extension
FORMAT_EXTENSIONS = {
    "text": ".txt",
    "markdown": ".md",
    "html": ".html",
    "json": ".json",
}

# Additional markers for extracting diff/msg (used with --diff flag)
DIFF_MARKERS_INSTRUCTION = """

ADDITIONALLY, at the end of your response, include these exact markers for automated extraction:
---COMMIT_MESSAGE_START---
(same commit message as above)
---COMMIT_MESSAGE_END---

---UNIFIED_DIFF_START---
(same unified diff as above)
---UNIFIED_DIFF_END---
"""

# Provider configurations
PROVIDERS = {
    "anthropic": {
        "name": "Claude",
        "endpoint": "https://api.anthropic.com/v1/messages",
        "default_model": "claude-sonnet-4-5-20250929",
        "env_var": "ANTHROPIC_API_KEY",
    },
    "openai": {
        "name": "ChatGPT",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "default_model": "gpt-4o",
        "env_var": "OPENAI_API_KEY",
    },
    "xai": {
        "name": "Grok",
        "endpoint": "https://api.x.ai/v1/chat/completions",
        "default_model": "grok-3",
        "env_var": "XAI_API_KEY",
    },
    "google": {
        "name": "Gemini",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta/models",
        "default_model": "gemini-2.0-flash",
        "env_var": "GOOGLE_API_KEY",
    },
}

# Commit prefix mappings based on file path
COMMIT_PREFIX_MAP = [
    ("doc/guides/prog_guide/", "doc/guides/prog_guide:"),
    ("doc/guides/sample_app_ug/", "doc/guides/sample_app:"),
    ("doc/guides/nics/", "doc/guides/nics:"),
    ("doc/guides/cryptodevs/", "doc/guides/cryptodevs:"),
    ("doc/guides/compressdevs/", "doc/guides/compressdevs:"),
    ("doc/guides/eventdevs/", "doc/guides/eventdevs:"),
    ("doc/guides/rawdevs/", "doc/guides/rawdevs:"),
    ("doc/guides/bbdevs/", "doc/guides/bbdevs:"),
    ("doc/guides/gpus/", "doc/guides/gpus:"),
    ("doc/guides/dmadevs/", "doc/guides/dmadevs:"),
    ("doc/guides/regexdevs/", "doc/guides/regexdevs:"),
    ("doc/guides/mldevs/", "doc/guides/mldevs:"),
    ("doc/guides/rel_notes/", "doc/guides/rel_notes:"),
    ("doc/guides/linux_gsg/", "doc/guides/linux_gsg:"),
    ("doc/guides/freebsd_gsg/", "doc/guides/freebsd_gsg:"),
    ("doc/guides/windows_gsg/", "doc/guides/windows_gsg:"),
    ("doc/guides/tools/", "doc/guides/tools:"),
    ("doc/guides/testpmd_app_ug/", "doc/guides/testpmd:"),
    ("doc/guides/howto/", "doc/guides/howto:"),
    ("doc/guides/contributing/", "doc/guides/contributing:"),
    ("doc/guides/platform/", "doc/guides/platform:"),
    ("doc/guides/", "doc:"),
    ("doc/api/", "doc/api:"),
    ("doc/", "doc:"),
]

SYSTEM_PROMPT = """\
You are an expert technical documentation reviewer for DPDK.
Your task is to review documentation files and suggest improvements for:
- Spelling errors
- Grammar issues
- Technical correctness
- Clarity and readability
- Consistency with DPDK terminology

IMPORTANT COMMIT MESSAGE RULES (from check-git-log.sh):
- Subject line MUST be ≤60 characters
- Format: "prefix: lowercase description"
- First word after colon must be lowercase (except acronyms like Rx, Tx, VF, MAC, API)
- Use imperative mood (e.g., "fix typo" not "fixed typo" or "fixes typo")
- NO trailing period on subject line
- NO punctuation marks: , ; ! ? & |
- NO underscores in subject after colon
- Body lines wrapped at 75 characters
- Body must NOT start with "It"
- Do NOT include Signed-off-by (user adds via git commit --sign)
- Only use "Fixes:" tag for actual errors in documentation, not style improvements

Case-sensitive terms (must use exact case):
- Rx, Tx (not RX, TX, rx, tx)
- VF, PF (not vf, pf)
- MAC, VLAN, RSS, API
- Linux, Windows, FreeBSD

For style/clarity improvements, do NOT use Fixes tag.
For actual errors (wrong information, broken examples), include Fixes tag \
if you can identify the commit."""

FORMAT_INSTRUCTIONS = {
    "text": """
OUTPUT FORMAT:
You must output exactly two sections:

1. COMMIT_MESSAGE section containing the complete commit message
2. UNIFIED_DIFF section containing the unified diff

Use these exact markers:
---COMMIT_MESSAGE_START---
(commit message here)
---COMMIT_MESSAGE_END---

---UNIFIED_DIFF_START---
(unified diff here)
---UNIFIED_DIFF_END---

The diff should be in unified format that can be applied with "git apply".
If no changes are needed, output empty sections with a note.""",
    "markdown": """
OUTPUT FORMAT:
Provide your review in Markdown format with:

## Summary
Brief description of changes

## Commit Message
```
(complete commit message here, ready to use)
```

## Changes
For each change:
### Issue N: Brief title
- **Location**: file path and line
- **Problem**: description
- **Fix**: suggested correction

## Unified Diff
```diff
(unified diff here)
```""",
    "html": """
OUTPUT FORMAT:
Provide your review in HTML format with:
- <h2> for sections (Summary, Commit Message, Changes, Diff)
- <pre><code> for commit message and diff
- <ul>/<li> for individual issues
- Do NOT include <html>, <head>, or <body> tags - just the content

Include sections for: Summary, Commit Message, Changes, Unified Diff""",
    "json": """
OUTPUT FORMAT:
Provide your review as JSON with this structure:
{
  "summary": "Brief description of changes",
  "commit_message": "Complete commit message ready to use",
  "changes": [
    {
      "type": "spelling|grammar|technical|clarity|style",
      "location": "line number or section",
      "original": "original text",
      "suggested": "corrected text",
      "reason": "why this change"
    }
  ],
  "diff": "unified diff as a string",
  "stats": {
    "total_issues": 0,
    "spelling": 0,
    "grammar": 0,
    "technical": 0,
    "clarity": 0
  }
}
Output ONLY valid JSON, no markdown code fences or other text.""",
}

USER_PROMPT = """\
Review the following DPDK documentation file and provide improvements.

File path: {doc_file}
Commit message prefix to use: {commit_prefix}

{format_instruction}

---DOCUMENT CONTENT---
"""


def error(msg):
    """Print error message and exit."""
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


def get_git_config(key):
    """Get a value from git config."""
    try:
        result = subprocess.run(
            ["git", "config", "--get", key],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def get_smtp_config():
    """Get SMTP configuration from git config sendemail settings."""
    config = {
        "server": get_git_config("sendemail.smtpserver"),
        "port": get_git_config("sendemail.smtpserverport"),
        "user": get_git_config("sendemail.smtpuser"),
        "encryption": get_git_config("sendemail.smtpencryption"),
        "password": get_git_config("sendemail.smtppass"),
    }

    # Set defaults
    if not config["port"]:
        if config["encryption"] == "ssl":
            config["port"] = "465"
        else:
            config["port"] = "587"

    # Convert port to int
    if config["port"]:
        config["port"] = int(config["port"])

    return config


def get_commit_prefix(filepath):
    """Determine commit message prefix from file path."""
    for prefix_path, prefix in COMMIT_PREFIX_MAP:
        if filepath.startswith(prefix_path):
            return prefix
    return "doc:"


def build_anthropic_request(
    model,
    max_tokens,
    agents_content,
    doc_content,
    doc_file,
    commit_prefix,
    output_format="text",
    include_diff_markers=False,
):
    """Build request payload for Anthropic API."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
    if include_diff_markers and output_format not in ("text", "json"):
        format_instruction += DIFF_MARKERS_INSTRUCTION
    user_prompt = USER_PROMPT.format(
        doc_file=doc_file,
        commit_prefix=commit_prefix,
        format_instruction=format_instruction,
    )
    return {
        "model": model,
        "max_tokens": max_tokens,
        "system": [
            {"type": "text", "text": SYSTEM_PROMPT},
            {
                "type": "text",
                "text": agents_content,
                "cache_control": {"type": "ephemeral"},
            },
        ],
        "messages": [
            {
                "role": "user",
                "content": user_prompt + doc_content,
            }
        ],
    }


def build_openai_request(
    model,
    max_tokens,
    agents_content,
    doc_content,
    doc_file,
    commit_prefix,
    output_format="text",
    include_diff_markers=False,
):
    """Build request payload for OpenAI-compatible APIs."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
    if include_diff_markers and output_format not in ("text", "json"):
        format_instruction += DIFF_MARKERS_INSTRUCTION
    user_prompt = USER_PROMPT.format(
        doc_file=doc_file,
        commit_prefix=commit_prefix,
        format_instruction=format_instruction,
    )
    return {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "system", "content": agents_content},
            {
                "role": "user",
                "content": user_prompt + doc_content,
            },
        ],
    }


def build_google_request(
    max_tokens,
    agents_content,
    doc_content,
    doc_file,
    commit_prefix,
    output_format="text",
    include_diff_markers=False,
):
    """Build request payload for Google Gemini API."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
    if include_diff_markers and output_format not in ("text", "json"):
        format_instruction += DIFF_MARKERS_INSTRUCTION
    user_prompt = USER_PROMPT.format(
        doc_file=doc_file,
        commit_prefix=commit_prefix,
        format_instruction=format_instruction,
    )
    return {
        "contents": [
            {"role": "user", "parts": [{"text": SYSTEM_PROMPT}]},
            {"role": "user", "parts": [{"text": agents_content}]},
            {
                "role": "user",
                "parts": [{"text": user_prompt + doc_content}],
            },
        ],
        "generationConfig": {"maxOutputTokens": max_tokens},
    }


def call_api(
    provider,
    api_key,
    model,
    max_tokens,
    agents_content,
    doc_content,
    doc_file,
    commit_prefix,
    output_format="text",
    include_diff_markers=False,
    verbose=False,
):
    """Make API request to the specified provider."""
    config = PROVIDERS[provider]

    # Build request based on provider
    if provider == "anthropic":
        request_data = build_anthropic_request(
            model,
            max_tokens,
            agents_content,
            doc_content,
            doc_file,
            commit_prefix,
            output_format,
            include_diff_markers,
        )
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        url = config["endpoint"]
    elif provider == "google":
        request_data = build_google_request(
            max_tokens,
            agents_content,
            doc_content,
            doc_file,
            commit_prefix,
            output_format,
            include_diff_markers,
        )
        headers = {"Content-Type": "application/json"}
        url = f"{config['endpoint']}/{model}:generateContent?key={api_key}"
    else:  # openai, xai
        request_data = build_openai_request(
            model,
            max_tokens,
            agents_content,
            doc_content,
            doc_file,
            commit_prefix,
            output_format,
            include_diff_markers,
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        url = config["endpoint"]

    # Make request
    request_body = json.dumps(request_data).encode("utf-8")
    req = Request(url, data=request_body, headers=headers, method="POST")

    try:
        with urlopen(req) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as e:
        error_body = e.read().decode("utf-8")
        try:
            error_data = json.loads(error_body)
            error(f"API error: {error_data.get('error', error_body)}")
        except json.JSONDecodeError:
            error(f"API error ({e.code}): {error_body}")
    except URLError as e:
        error(f"Connection error: {e.reason}")

    # Show verbose info
    if verbose:
        print("=== Token Usage ===", file=sys.stderr)
        if provider == "anthropic":
            usage = result.get("usage", {})
            print(f"Input tokens: {usage.get('input_tokens', 'N/A')}", file=sys.stderr)
            print(
                f"Cache creation: " f"{usage.get('cache_creation_input_tokens', 0)}",
                file=sys.stderr,
            )
            print(
                f"Cache read: {usage.get('cache_read_input_tokens', 0)}",
                file=sys.stderr,
            )
            print(
                f"Output tokens: {usage.get('output_tokens', 'N/A')}", file=sys.stderr
            )
        elif provider == "google":
            usage = result.get("usageMetadata", {})
            print(
                f"Prompt tokens: {usage.get('promptTokenCount', 'N/A')}",
                file=sys.stderr,
            )
            print(
                f"Output tokens: {usage.get('candidatesTokenCount', 'N/A')}",
                file=sys.stderr,
            )
        else:  # openai, xai
            usage = result.get("usage", {})
            print(
                f"Prompt tokens: {usage.get('prompt_tokens', 'N/A')}", file=sys.stderr
            )
            print(
                f"Completion tokens: " f"{usage.get('completion_tokens', 'N/A')}",
                file=sys.stderr,
            )
        print("===================", file=sys.stderr)

    # Extract response text
    if provider == "anthropic":
        if "error" in result:
            error(f"API error: {result['error'].get('message', result)}")
        content = result.get("content", [])
        return "".join(
            block.get("text", "") for block in content if block.get("type") == "text"
        )
    elif provider == "google":
        if "error" in result:
            error(f"API error: {result['error'].get('message', result)}")
        candidates = result.get("candidates", [])
        if not candidates:
            error("No response from Gemini")
        parts = candidates[0].get("content", {}).get("parts", [])
        return "".join(part.get("text", "") for part in parts)
    else:  # openai, xai
        if "error" in result:
            error(f"API error: {result['error'].get('message', result)}")
        choices = result.get("choices", [])
        if not choices:
            error("No response from API")
        return choices[0].get("message", {}).get("content", "")


def parse_review_text(review_text):
    """Extract commit message and diff from text format response."""
    commit_msg = ""
    diff = ""

    # Extract commit message
    msg_match = re.search(
        r"---COMMIT_MESSAGE_START---\s*\n(.*?)\n---COMMIT_MESSAGE_END---",
        review_text,
        re.DOTALL,
    )
    if msg_match:
        commit_msg = msg_match.group(1).strip()

    # Extract unified diff
    diff_match = re.search(
        r"---UNIFIED_DIFF_START---\s*\n(.*?)\n---UNIFIED_DIFF_END---",
        review_text,
        re.DOTALL,
    )
    if diff_match:
        diff = diff_match.group(1).strip()
        # Clean up any markdown code fence if present
        diff = re.sub(r"^```diff\s*\n?", "", diff)
        diff = re.sub(r"\n?```\s*$", "", diff)

    return commit_msg, diff


def strip_diff_markers(text):
    """Remove the diff/msg extraction markers from text."""
    # Remove commit message markers and content
    text = re.sub(
        r"\n*---COMMIT_MESSAGE_START---\s*\n.*?\n---COMMIT_MESSAGE_END---\s*",
        "",
        text,
        flags=re.DOTALL,
    )
    # Remove unified diff markers and content
    text = re.sub(
        r"\n*---UNIFIED_DIFF_START---\s*\n.*?\n---UNIFIED_DIFF_END---\s*",
        "",
        text,
        flags=re.DOTALL,
    )
    return text.strip()


def send_email(
    to_addrs,
    cc_addrs,
    from_addr,
    subject,
    in_reply_to,
    body,
    dry_run=False,
    verbose=False,
):
    """Send review email via SMTP using git sendemail config."""
    # Build email message
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

    if dry_run:
        print("=== Email Preview (dry-run) ===", file=sys.stderr)
        print(msg.as_string(), file=sys.stderr)
        print("=== End Preview ===", file=sys.stderr)
        return True

    # Get SMTP configuration from git config
    smtp_config = get_smtp_config()

    if not smtp_config["server"]:
        error("No SMTP server configured. Set git config sendemail.smtpserver")

    server = smtp_config["server"]
    port = smtp_config["port"]
    user = smtp_config["user"]
    encryption = smtp_config["encryption"]

    # Get password from environment or git config, or prompt
    password = os.environ.get("SMTP_PASSWORD") or smtp_config["password"]
    if user and not password:
        password = getpass.getpass(f"SMTP password for {user}@{server}: ")

    if verbose:
        print(f"SMTP server: {server}:{port}", file=sys.stderr)
        print(f"SMTP user: {user or '(none)'}", file=sys.stderr)
        print(f"Encryption: {encryption or 'starttls'}", file=sys.stderr)

    # Collect all recipients
    all_recipients = list(to_addrs)
    if cc_addrs:
        all_recipients.extend(cc_addrs)

    try:
        if encryption == "ssl":
            # SSL/TLS connection from the start (port 465)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(server, port, context=context) as smtp:
                if user and password:
                    smtp.login(user, password)
                smtp.send_message(msg, from_addr, all_recipients)
        else:
            # STARTTLS (port 587) or plain (port 25)
            with smtplib.SMTP(server, port) as smtp:
                smtp.ehlo()
                if encryption == "tls" or port == 587:
                    context = ssl.create_default_context()
                    smtp.starttls(context=context)
                    smtp.ehlo()
                if user and password:
                    smtp.login(user, password)
                smtp.send_message(msg, from_addr, all_recipients)

        print(f"Email sent via SMTP ({server}:{port})", file=sys.stderr)
        return True

    except smtplib.SMTPAuthenticationError as e:
        error(f"SMTP authentication failed: {e}")
    except smtplib.SMTPException as e:
        error(f"SMTP error: {e}")
    except OSError as e:
        error(f"Connection error to {server}:{port}: {e}")


def list_providers():
    """Print available providers and exit."""
    print("Available AI Providers:\n")
    print(f"{'Provider':<12} {'Default Model':<30} {'API Key Variable'}")
    print(f"{'--------':<12} {'-------------':<30} {'----------------'}")
    for name, config in PROVIDERS.items():
        print(f"{name:<12} {config['default_model']:<30} {config['env_var']}")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="Review DPDK documentation files using AI providers. "
        "Accepts multiple files and generates output for each.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s doc/guides/prog_guide/mempool_lib.rst
    %(prog)s doc/guides/nics/*.rst              # Review all NIC docs
    %(prog)s -p openai -o /tmp doc/guides/nics/ixgbe.rst doc/guides/nics/i40e.rst
    %(prog)s -f html -d -o /tmp/reviews doc/guides/nics/*.rst  # HTML + diff files
    %(prog)s -f json -o /tmp doc/guides/howto/flow_bifurcation.rst
    %(prog)s --send-email --to dev@dpdk.org doc/guides/nics/ixgbe.rst

Output files (in output-dir):
    <basename>.txt|.md|.html|.json  Review in selected format
    <basename>.diff                  Unified diff (text/json, or with --diff)
    <basename>.msg                   Commit message (text/json, or with --diff)

After review:
    git apply <basename>.diff
    git commit -sF <basename>.msg

SMTP Configuration (from git config):
    sendemail.smtpserver      SMTP server hostname
    sendemail.smtpserverport  SMTP port (default: 587 for TLS, 465 for SSL)
    sendemail.smtpuser        SMTP username
    sendemail.smtpencryption  'tls' for STARTTLS, 'ssl' for SSL/TLS
    sendemail.smtppass        SMTP password (or set SMTP_PASSWORD env var)

Example git config:
    git config --global sendemail.smtpserver smtp.gmail.com
    git config --global sendemail.smtpserverport 587
    git config --global sendemail.smtpuser yourname@gmail.com
    git config --global sendemail.smtpencryption tls
        """,
    )

    parser.add_argument(
        "doc_files",
        nargs="+",
        metavar="doc_file",
        help="Documentation file(s) to review",
    )
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
        default=8192,
        help="Max tokens for response (default: 8192)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Output directory for all output files (default: .)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show API request details",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress review output to stdout (only write files)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=OUTPUT_FORMATS,
        default="text",
        dest="output_format",
        help="Output format: text, markdown, html, json (default: text)",
    )
    parser.add_argument(
        "-d",
        "--diff",
        action="store_true",
        help="Always produce .diff and .msg files (automatic for text/json)",
    )
    parser.add_argument(
        "-l",
        "--list-providers",
        action="store_true",
        help="List available providers and exit",
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

    # Get provider config
    config = PROVIDERS[args.provider]
    model = args.model or config["default_model"]

    # Get API key
    api_key = os.environ.get(config["env_var"])
    if not api_key:
        error(f"{config['env_var']} environment variable not set")

    # Validate files
    agents_path = Path(args.agents)
    if not agents_path.exists():
        error(f"AGENTS.md not found: {args.agents}")

    # Validate all doc files exist before processing
    doc_paths = []
    for doc_file in args.doc_files:
        doc_path = Path(doc_file)
        if not doc_path.exists():
            error(f"Documentation file not found: {doc_file}")
        doc_paths.append((doc_file, doc_path))

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

    # Read AGENTS.md once
    agents_content = agents_path.read_text()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    provider_name = config["name"]

    # Process each file
    num_files = len(doc_paths)
    for file_idx, (doc_file, doc_path) in enumerate(doc_paths, 1):
        if num_files > 1:
            print(
                f"\n{'=' * 60}",
                file=sys.stderr,
            )
            print(
                f"Processing file {file_idx}/{num_files}: {doc_file}",
                file=sys.stderr,
            )
            print(
                f"{'=' * 60}",
                file=sys.stderr,
            )

        # Determine output filenames
        doc_basename = doc_path.stem
        diff_file = output_dir / f"{doc_basename}.diff"
        msg_file = output_dir / f"{doc_basename}.msg"

        # Get commit prefix
        commit_prefix = get_commit_prefix(doc_file)

        # Read doc content
        doc_content = doc_path.read_text()

        if args.verbose:
            print("=== Request ===", file=sys.stderr)
            print(f"Provider: {args.provider}", file=sys.stderr)
            print(f"Model: {model}", file=sys.stderr)
            print(f"Output format: {args.output_format}", file=sys.stderr)
            print(f"AGENTS file: {args.agents}", file=sys.stderr)
            print(f"Doc file: {doc_file}", file=sys.stderr)
            print(f"Commit prefix: {commit_prefix}", file=sys.stderr)
            print(f"Output dir: {args.output_dir}", file=sys.stderr)
            if args.send_email:
                print("Send email: yes", file=sys.stderr)
                print(f"To: {', '.join(args.to_addrs)}", file=sys.stderr)
                if args.cc_addrs:
                    print(f"Cc: {', '.join(args.cc_addrs)}", file=sys.stderr)
                print(f"From: {from_addr}", file=sys.stderr)
            print("===============", file=sys.stderr)

        # Call API
        review_text = call_api(
            args.provider,
            api_key,
            model,
            args.tokens,
            agents_content,
            doc_content,
            doc_file,
            commit_prefix,
            args.output_format,
            args.diff,
            args.verbose,
        )

        if not review_text:
            print(
                f"Warning: No response received for {doc_file}",
                file=sys.stderr,
            )
            continue

        # Determine review output file
        format_ext = FORMAT_EXTENSIONS[args.output_format]
        review_file = output_dir / f"{doc_basename}{format_ext}"

        # Determine if we should write diff/msg files
        write_diff_msg = args.diff or args.output_format in ("text", "json")

        # Extract commit message and diff first (before stripping markers)
        commit_msg, diff = "", ""
        if write_diff_msg:
            if args.output_format == "json":
                # Will extract from JSON below
                pass
            else:
                # Parse from text format markers
                commit_msg, diff = parse_review_text(review_text)

        # For non-text formats with --diff, strip the markers from display output
        display_text = review_text
        if args.diff and args.output_format in ("markdown", "html"):
            display_text = strip_diff_markers(review_text)

        # Build formatted output text
        if args.output_format == "text":
            output_text = review_text
        elif args.output_format == "json":
            # Try to parse JSON response
            try:
                review_data = json.loads(review_text)
            except json.JSONDecodeError:
                print("Warning: Response is not valid JSON", file=sys.stderr)
                review_data = {"raw_response": review_text}

            # Extract diff/msg from JSON if present
            if write_diff_msg:
                if isinstance(review_data, dict) and "raw_response" not in review_data:
                    commit_msg = review_data.get("commit_message", "")
                    diff = review_data.get("diff", "")

            # Add metadata
            output_data = {
                "metadata": {
                    "doc_file": doc_file,
                    "provider": args.provider,
                    "provider_name": provider_name,
                    "model": model,
                    "commit_prefix": commit_prefix,
                },
                "review": review_data,
            }
            output_text = json.dumps(output_data, indent=2)
        elif args.output_format == "markdown":
            output_text = f"""# Documentation Review: {doc_path.name}

*Reviewed by {provider_name} ({model})*

{display_text}
"""
        elif args.output_format == "html":
            output_text = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Review: {doc_path.name}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2em auto; padding: 0 1em; }}
h1 {{ color: #333; }}
.review-meta {{ color: #666; font-style: italic; }}
pre {{ background: #f5f5f5; padding: 1em; overflow-x: auto; }}
</style>
</head>
<body>
<h1>Documentation Review: {doc_path.name}</h1>
<p class="review-meta">Reviewed by {provider_name} ({model})</p>
<div class="review-content">
{display_text}
</div>
</body>
</html>
"""

        # Write formatted review to file
        review_file.write_text(output_text)
        print(f"Review written to: {review_file}", file=sys.stderr)

        # Write diff/msg files
        if write_diff_msg:
            if commit_msg:
                msg_file.write_text(commit_msg + "\n")
                print(f"Commit message written to: {msg_file}", file=sys.stderr)
            else:
                msg_file.write_text("# No commit message generated\n")
                print("Warning: Could not extract commit message", file=sys.stderr)

            if diff:
                diff_file.write_text(diff + "\n")
                print(f"Diff written to: {diff_file}", file=sys.stderr)
            else:
                diff_file.write_text("# No changes suggested\n")
                print("Warning: Could not extract diff", file=sys.stderr)

        # Print to stdout unless quiet (or multiple files without verbose)
        show_stdout = not args.quiet and (num_files == 1 or args.verbose)
        if show_stdout:
            print(
                f"\n=== Documentation Review: {doc_path.name} "
                f"(via {provider_name}) ==="
            )
            print(output_text)

            # Print usage instructions for text format
            if args.output_format == "text":
                print("\n=== Output Files ===")
                print(f"Commit message: {msg_file}")
                print(f"Diff file:      {diff_file}")
                print("\nTo apply changes:")
                print(f"  git apply {diff_file}")
                print(f"  git commit -sF {msg_file}")

        # Send email if requested
        if args.send_email:
            if args.output_format != "text":
                print(
                    f"Note: Email will be sent as plain text regardless of "
                    f"--format={args.output_format}",
                    file=sys.stderr,
                )

            review_subject = f"[REVIEW] {commit_prefix} {doc_path.name}"

            # Build email body
            email_body = f"""AI-generated documentation review of {doc_file}
Reviewed using {provider_name} ({model})

This is an automated review. Please verify all suggestions.

---

{review_text}
"""

            if args.verbose:
                print("", file=sys.stderr)
                print("=== Email Details ===", file=sys.stderr)
                print(f"Subject: {review_subject}", file=sys.stderr)
                print("=====================", file=sys.stderr)

            send_email(
                args.to_addrs,
                args.cc_addrs,
                from_addr,
                review_subject,
                None,
                email_body,
                args.dry_run,
                args.verbose,
            )

            if not args.dry_run:
                print("", file=sys.stderr)
                print(f"Review sent to: {', '.join(args.to_addrs)}", file=sys.stderr)

    # Print summary for multiple files
    if num_files > 1:
        print(f"\n{'=' * 60}", file=sys.stderr)
        print(f"Processed {num_files} files", file=sys.stderr)
        print(f"Output directory: {output_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
