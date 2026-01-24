#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

"""
Analyze DPDK patches using AI providers.

Supported providers: Anthropic Claude, OpenAI ChatGPT, xAI Grok, Google Gemini
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from email.message import EmailMessage
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Output formats
OUTPUT_FORMATS = ["text", "markdown", "html", "json"]

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
  "overall_status": "PASS|WARN|FAIL"
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


def build_anthropic_request(
    model, max_tokens, agents_content, patch_content, patch_name, output_format="text"
):
    """Build request payload for Anthropic API."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
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
    model, max_tokens, agents_content, patch_content, patch_name, output_format="text"
):
    """Build request payload for OpenAI-compatible APIs."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
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
    max_tokens, agents_content, patch_content, patch_name, output_format="text"
):
    """Build request payload for Google Gemini API."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
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
    verbose=False,
):
    """Make API request to the specified provider."""
    config = PROVIDERS[provider]

    # Build request based on provider
    if provider == "anthropic":
        request_data = build_anthropic_request(
            model, max_tokens, agents_content, patch_content, patch_name, output_format
        )
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        url = config["endpoint"]
    elif provider == "google":
        request_data = build_google_request(
            max_tokens, agents_content, patch_content, patch_name, output_format
        )
        headers = {"Content-Type": "application/json"}
        url = f"{config['endpoint']}/{model}:generateContent?key={api_key}"
    else:  # openai, xai
        request_data = build_openai_request(
            model, max_tokens, agents_content, patch_content, patch_name, output_format
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
    to_addrs, cc_addrs, from_addr, subject, in_reply_to, body, dry_run=False
):
    """Send review email using git send-email, sendmail, or msmtp."""
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
            cmd = ["git", "send-email", "--confirm=never", "--quiet"]
            cmd.extend(["--to", addr] for addr in to_addrs)
            # Flatten the list
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

        error("Could not send email. Configure git send-email, sendmail, " "or msmtp.")

    finally:
        os.unlink(temp_file)


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
        description="Analyze DPDK patches using AI providers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s patch.patch                    # Review with default settings
    %(prog)s -p openai my-patch.patch       # Use OpenAI ChatGPT
    %(prog)s -f markdown patch.patch        # Output as Markdown
    %(prog)s -f json -o review.json patch.patch  # Save JSON to file
    %(prog)s -f html -o review.html patch.patch  # Save HTML to file
    %(prog)s --send-email --to dev@dpdk.org series.mbox
    %(prog)s --send-email --to dev@dpdk.org --dry-run series.mbox
        """,
    )

    parser.add_argument("patch_file", nargs="?", help="Patch file to analyze")
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

    # Get API key
    api_key = os.environ.get(config["env_var"])
    if not api_key:
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

    # Read files
    agents_content = agents_path.read_text()
    patch_content = patch_path.read_text()
    patch_name = patch_path.name

    if args.verbose:
        print("=== Request ===", file=sys.stderr)
        print(f"Provider: {args.provider}", file=sys.stderr)
        print(f"Model: {model}", file=sys.stderr)
        print(f"Output format: {args.output_format}", file=sys.stderr)
        print(f"AGENTS file: {args.agents}", file=sys.stderr)
        print(f"Patch file: {args.patch_file}", file=sys.stderr)
        if args.output:
            print(f"Output file: {args.output}", file=sys.stderr)
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
        args.verbose,
    )

    if not review_text:
        error(f"No response received from {args.provider}")

    # Format output based on requested format
    provider_name = config["name"]

    if args.output_format == "json":
        # For JSON, try to parse and add metadata
        try:
            review_data = json.loads(review_text)
        except json.JSONDecodeError:
            # If AI didn't return valid JSON, wrap the text
            review_data = {"raw_review": review_text}

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
    elif args.output_format == "html":
        # Wrap HTML content with header
        output_text = f"""<!-- AI-generated review of {patch_name} -->
<!-- Reviewed using {provider_name} ({model}) -->
<div class="patch-review">
<h1>Patch Review: {patch_name}</h1>
<p class="review-meta">Reviewed by {provider_name} ({model})</p>
{review_text}
</div>
"""
    elif args.output_format == "markdown":
        output_text = f"""# Patch Review: {patch_name}

*Reviewed by {provider_name} ({model})*

{review_text}
"""
    else:  # text
        output_text = f"=== Patch Review: {patch_name} (via {provider_name}) ===\n\n"
        output_text += review_text

    # Write output
    if args.output:
        Path(args.output).write_text(output_text)
        print(f"Review written to: {args.output}", file=sys.stderr)
    else:
        print(output_text)

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
        )

        if not args.dry_run:
            print("", file=sys.stderr)
            print(f"Review sent to: {', '.join(args.to_addrs)}", file=sys.stderr)


if __name__ == "__main__":
    main()
