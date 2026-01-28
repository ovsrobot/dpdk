#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

"""
Analyze DPDK patches using AI providers.

Accepts multiple patch files and generates output for each.
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
(corrected commit message if changes needed, or original if acceptable)
---COMMIT_MESSAGE_END---

---UNIFIED_DIFF_START---
(unified diff showing suggested changes to the patch, or "No changes needed" if acceptable)
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

SYSTEM_PROMPT = """You are an expert DPDK code reviewer. Analyze patches for \
compliance with DPDK coding standards and contribution guidelines. Provide \
clear, actionable feedback organized by severity (Error, Warning, Info) as \
defined in the guidelines."""

FORMAT_INSTRUCTIONS = {
    "text": """Provide your review in plain text format.""",
    "markdown": """Provide your review in Markdown format with:
- Headers (##) for each severity level (Errors, Warnings, Info)
- Bullet points for individual issues
- Code blocks (```) for code references
- Bold (**) for emphasis on key points""",
    "html": """Provide your review in HTML format with:
- <h2> tags for each severity level (Errors, Warnings, Info)
- <ul>/<li> for individual issues
- <pre><code> for code references
- <strong> for emphasis on key points
- Use appropriate semantic HTML tags
- Do NOT include <html>, <head>, or <body> tags - just the content""",
    "json": """Provide your review in JSON format with this structure:
{
  "summary": "Brief one-line summary of the review",
  "errors": [
    {"issue": "description", "location": "file:line", "suggestion": "fix"}
  ],
  "warnings": [
    {"issue": "description", "location": "file:line", "suggestion": "fix"}
  ],
  "info": [
    {"issue": "description", "location": "file:line", "suggestion": "fix"}
  ],
  "passed_checks": ["list of checks that passed"],
  "overall_status": "PASS|WARN|FAIL",
  "corrected_commit_message": "corrected commit message if needed",
  "suggested_diff": "unified diff of suggested changes"
}
Output ONLY valid JSON, no markdown code fences or other text.""",
}

USER_PROMPT = """Please review the following DPDK patch file '{patch_name}' \
against the AGENTS.md guidelines. Check for:

1. Commit message format (subject line, body, tags)
2. License/copyright compliance
3. C coding style issues
4. API and documentation requirements
5. Any other guideline violations

{format_instruction}

--- PATCH CONTENT ---
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


def build_anthropic_request(
    model,
    max_tokens,
    agents_content,
    patch_content,
    patch_name,
    output_format="text",
    include_diff_markers=False,
):
    """Build request payload for Anthropic API."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
    if include_diff_markers and output_format not in ("text", "json"):
        format_instruction += DIFF_MARKERS_INSTRUCTION
    user_prompt = USER_PROMPT.format(
        patch_name=patch_name, format_instruction=format_instruction
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
                "content": user_prompt + patch_content,
            }
        ],
    }


def build_openai_request(
    model,
    max_tokens,
    agents_content,
    patch_content,
    patch_name,
    output_format="text",
    include_diff_markers=False,
):
    """Build request payload for OpenAI-compatible APIs."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
    if include_diff_markers and output_format not in ("text", "json"):
        format_instruction += DIFF_MARKERS_INSTRUCTION
    user_prompt = USER_PROMPT.format(
        patch_name=patch_name, format_instruction=format_instruction
    )
    return {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "system", "content": agents_content},
            {
                "role": "user",
                "content": user_prompt + patch_content,
            },
        ],
    }


def build_google_request(
    max_tokens,
    agents_content,
    patch_content,
    patch_name,
    output_format="text",
    include_diff_markers=False,
):
    """Build request payload for Google Gemini API."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
    if include_diff_markers and output_format not in ("text", "json"):
        format_instruction += DIFF_MARKERS_INSTRUCTION
    user_prompt = USER_PROMPT.format(
        patch_name=patch_name, format_instruction=format_instruction
    )
    return {
        "contents": [
            {"role": "user", "parts": [{"text": SYSTEM_PROMPT}]},
            {"role": "user", "parts": [{"text": agents_content}]},
            {
                "role": "user",
                "parts": [{"text": user_prompt + patch_content}],
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
    patch_content,
    patch_name,
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
            patch_content,
            patch_name,
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
            patch_content,
            patch_name,
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
            patch_content,
            patch_name,
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


def get_last_message_id(patch_content):
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


def get_last_subject(patch_content):
    """Extract subject from the last patch in an mbox."""
    # Find all Subject lines with potential continuations
    subjects = []
    lines = patch_content.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].lower().startswith("subject:"):
            subject = lines[i][8:].strip()
            i += 1
            # Handle continuation lines
            while i < len(lines) and lines[i].startswith((" ", "\t")):
                subject += lines[i].strip()
                i += 1
            subjects.append(subject)
        else:
            i += 1
    return subjects[-1] if subjects else None


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
        description="Analyze DPDK patches using AI providers. "
        "Accepts multiple files and generates output for each.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s patch.patch                    # Review with default settings
    %(prog)s *.patch                        # Review multiple patches
    %(prog)s -p openai 0001-*.patch         # Use OpenAI ChatGPT
    %(prog)s -f markdown -o /tmp patch.patch  # Output as Markdown
    %(prog)s -f json -o /tmp *.patch        # Save JSON reviews to directory
    %(prog)s -d -o /tmp patch.patch         # Generate diff and msg files
    %(prog)s --send-email --to dev@dpdk.org series.mbox
    %(prog)s --send-email --to dev@dpdk.org --dry-run series.mbox

Output files (in output-dir):
    <basename>.txt|.md|.html|.json  Review in selected format
    <basename>.diff                  Suggested changes (with --diff)
    <basename>.msg                   Corrected commit message (with --diff)

SMTP Configuration (from git config):
    sendemail.smtpserver      SMTP server hostname
    sendemail.smtpserverport  SMTP port (default: 587 for TLS, 465 for SSL)
    sendemail.smtpuser        SMTP username
    sendemail.smtpencryption  'tls' for STARTTLS, 'ssl' for SSL/TLS
    sendemail.smtppass        SMTP password (or set SMTP_PASSWORD env var)
        """,
    )

    parser.add_argument(
        "patch_files",
        nargs="+",
        metavar="patch_file",
        help="Patch file(s) to analyze",
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
        default=4096,
        help="Max tokens for response (default: 4096)",
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
        help="Produce .diff and .msg files with suggested corrections",
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

    # Validate AGENTS.md exists
    agents_path = Path(args.agents)
    if not agents_path.exists():
        error(f"AGENTS.md not found: {args.agents}")

    # Validate all patch files exist before processing
    patch_paths = []
    for patch_file in args.patch_files:
        patch_path = Path(patch_file)
        if not patch_path.exists():
            error(f"Patch file not found: {patch_file}")
        patch_paths.append((patch_file, patch_path))

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
    num_files = len(patch_paths)
    for file_idx, (patch_file, patch_path) in enumerate(patch_paths, 1):
        if num_files > 1:
            print(
                f"\n{'=' * 60}",
                file=sys.stderr,
            )
            print(
                f"Processing file {file_idx}/{num_files}: {patch_file}",
                file=sys.stderr,
            )
            print(
                f"{'=' * 60}",
                file=sys.stderr,
            )

        # Determine output filenames
        patch_basename = patch_path.stem
        diff_file = output_dir / f"{patch_basename}.diff"
        msg_file = output_dir / f"{patch_basename}.msg"

        # Read patch content
        patch_content = patch_path.read_text()
        patch_name = patch_path.name

        if args.verbose:
            print("=== Request ===", file=sys.stderr)
            print(f"Provider: {args.provider}", file=sys.stderr)
            print(f"Model: {model}", file=sys.stderr)
            print(f"Output format: {args.output_format}", file=sys.stderr)
            print(f"AGENTS file: {args.agents}", file=sys.stderr)
            print(f"Patch file: {patch_file}", file=sys.stderr)
            print(f"Output dir: {args.output_dir}", file=sys.stderr)
            if args.diff:
                print("Generate diff: yes", file=sys.stderr)
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
            patch_content,
            patch_name,
            args.output_format,
            args.diff,
            args.verbose,
        )

        if not review_text:
            print(
                f"Warning: No response received for {patch_file}",
                file=sys.stderr,
            )
            continue

        # Determine review output file
        format_ext = FORMAT_EXTENSIONS[args.output_format]
        review_file = output_dir / f"{patch_basename}{format_ext}"

        # Extract commit message and diff if requested
        commit_msg, diff = "", ""
        if args.diff:
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
            output_text = (
                f"=== Patch Review: {patch_name} (via {provider_name}) ===\n\n"
            )
            output_text += review_text
        elif args.output_format == "json":
            # Try to parse JSON response
            try:
                review_data = json.loads(review_text)
            except json.JSONDecodeError:
                print("Warning: Response is not valid JSON", file=sys.stderr)
                review_data = {"raw_response": review_text}

            # Extract diff/msg from JSON if present
            if args.diff:
                if isinstance(review_data, dict) and "raw_response" not in review_data:
                    commit_msg = review_data.get("corrected_commit_message", "")
                    diff = review_data.get("suggested_diff", "")

            # Add metadata
            output_data = {
                "metadata": {
                    "patch_file": patch_name,
                    "provider": args.provider,
                    "provider_name": provider_name,
                    "model": model,
                },
                "review": review_data,
            }
            output_text = json.dumps(output_data, indent=2)
        elif args.output_format == "markdown":
            output_text = f"""# Patch Review: {patch_name}

*Reviewed by {provider_name} ({model})*

{display_text}
"""
        elif args.output_format == "html":
            output_text = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Review: {patch_name}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2em auto; padding: 0 1em; }}
h1 {{ color: #333; }}
.review-meta {{ color: #666; font-style: italic; }}
pre {{ background: #f5f5f5; padding: 1em; overflow-x: auto; }}
</style>
</head>
<body>
<h1>Patch Review: {patch_name}</h1>
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

        # Write diff/msg files if requested
        if args.diff:
            if commit_msg:
                msg_file.write_text(commit_msg + "\n")
                print(f"Commit message written to: {msg_file}", file=sys.stderr)
            else:
                msg_file.write_text("# No commit message corrections suggested\n")
                print("Note: No commit message corrections extracted", file=sys.stderr)

            if diff and diff.lower() != "no changes needed":
                diff_file.write_text(diff + "\n")
                print(f"Diff written to: {diff_file}", file=sys.stderr)
            else:
                diff_file.write_text("# No changes suggested\n")
                print("Note: No code changes suggested", file=sys.stderr)

        # Print to stdout unless quiet (or multiple files without verbose)
        show_stdout = not args.quiet and (num_files == 1 or args.verbose)
        if show_stdout:
            print(output_text)

            # Print usage instructions if diff files were generated
            if args.diff:
                print("\n=== Output Files ===")
                print(f"Review:         {review_file}")
                print(f"Commit message: {msg_file}")
                print(f"Diff file:      {diff_file}")

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
            email_body = f"""AI-generated review of {patch_name}
Reviewed using {provider_name} ({model})

This is an automated review. Please verify all suggestions.

---

{review_text}
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
