#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

# Analyze DPDK patches using various AI providers
# Supported providers: anthropic (Claude), openai (ChatGPT), xai (Grok), google (Gemini)

set -e

# Default paths and settings
AGENTS_FILE="AGENTS.md"
MAX_TOKENS=4096
PROVIDER="anthropic"

# Temporary file for API requests (cleaned up on exit)
REQUEST_FILE=""
cleanup() {
    [[ -n "$REQUEST_FILE" && -f "$REQUEST_FILE" ]] && rm -f "$REQUEST_FILE"
}
trap cleanup EXIT

# Default models per provider
declare -A DEFAULT_MODELS=(
    ["anthropic"]="claude-sonnet-4-5-20250929"
    ["openai"]="gpt-4o"
    ["xai"]="grok-3"
    ["google"]="gemini-2.0-flash"
)

# API endpoints per provider
declare -A API_ENDPOINTS=(
    ["anthropic"]="https://api.anthropic.com/v1/messages"
    ["openai"]="https://api.openai.com/v1/chat/completions"
    ["xai"]="https://api.x.ai/v1/chat/completions"
    ["google"]="https://generativelanguage.googleapis.com/v1beta/models"
)

# Environment variable names for API keys
declare -A API_KEY_VARS=(
    ["anthropic"]="ANTHROPIC_API_KEY"
    ["openai"]="OPENAI_API_KEY"
    ["xai"]="XAI_API_KEY"
    ["google"]="GOOGLE_API_KEY"
)

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <patch-file>

Analyze a DPDK patch file against AGENTS.md review guidelines using AI.

Options:
    -p, --provider NAME  AI provider: anthropic, openai, xai, google
                         (default: anthropic)
    -a, --agents FILE    Path to AGENTS.md file (default: AGENTS.md)
    -m, --model MODEL    Model to use (provider-specific, see defaults below)
    -t, --tokens NUM     Max tokens for response (default: $MAX_TOKENS)
    -v, --verbose        Show API request details
    -l, --list-providers List available providers and their defaults
    -h, --help           Show this help message

Providers and Default Models:
    anthropic    Claude (claude-sonnet-4-5-20250929)
    openai       ChatGPT (gpt-4o)
    xai          Grok (grok-3)
    google       Gemini (gemini-2.0-flash)

Environment Variables (set the one for your chosen provider):
    ANTHROPIC_API_KEY    For Anthropic Claude
    OPENAI_API_KEY       For OpenAI ChatGPT
    XAI_API_KEY          For xAI Grok
    GOOGLE_API_KEY       For Google Gemini

Examples:
    $(basename "$0") 0001-net-ixgbe-fix-something.patch
    $(basename "$0") -p openai my-patch.patch
    $(basename "$0") -p xai -m grok-3 my-patch.patch
    $(basename "$0") -p google --verbose *.patch
EOF
    exit "${1:-0}"
}

list_providers() {
    echo "Available AI Providers:"
    echo ""
    printf "%-12s %-35s %s\n" "Provider" "Default Model" "API Key Variable"
    printf "%-12s %-35s %s\n" "--------" "-------------" "----------------"
    for provider in anthropic openai xai google; do
        printf "%-12s %-35s %s\n" "$provider" "${DEFAULT_MODELS[$provider]}" "${API_KEY_VARS[$provider]}"
    done
    exit 0
}

error() {
    echo "Error: $1" >&2
    exit 1
}

# Read file contents, escaping for JSON
read_json_escaped() {
    local file="$1"
    python3 -c "
import json
with open('$file', 'r') as f:
    print(json.dumps(f.read()))
"
}

# Build request for Anthropic Claude API
build_anthropic_request() {
    local model="$1"
    local max_tokens="$2"
    local agents_content="$3"
    local patch_content="$4"
    local patch_name="$5"

    cat <<EOF
{
    "model": "$model",
    "max_tokens": $max_tokens,
    "system": [
        {
            "type": "text",
            "text": "You are an expert DPDK code reviewer. Analyze patches for compliance with DPDK coding standards and contribution guidelines. Provide clear, actionable feedback organized by severity (Error, Warning, Info) as defined in the guidelines."
        },
        {
            "type": "text",
            "text": $agents_content,
            "cache_control": {"type": "ephemeral"}
        }
    ],
    "messages": [
        {
            "role": "user",
            "content": "Please review the following DPDK patch file '$patch_name' against the AGENTS.md guidelines. Check for:\n\n1. Commit message format (subject line, body, tags)\n2. License/copyright compliance\n3. C coding style issues\n4. API and documentation requirements\n5. Any other guideline violations\n\nProvide feedback organized by severity level.\n\n--- PATCH CONTENT ---\n"
        },
        {
            "role": "user",
            "content": $patch_content
        }
    ]
}
EOF
}

# Build request for OpenAI-compatible APIs (OpenAI, xAI)
build_openai_request() {
    local model="$1"
    local max_tokens="$2"
    local agents_content="$3"
    local patch_content="$4"
    local patch_name="$5"

    cat <<EOF
{
    "model": "$model",
    "max_tokens": $max_tokens,
    "messages": [
        {
            "role": "system",
            "content": "You are an expert DPDK code reviewer. Analyze patches for compliance with DPDK coding standards and contribution guidelines. Provide clear, actionable feedback organized by severity (Error, Warning, Info) as defined in the guidelines.\n\nHere are the DPDK review guidelines:\n\n"
        },
        {
            "role": "system",
            "content": $agents_content
        },
        {
            "role": "user",
            "content": "Please review the following DPDK patch file '$patch_name' against the AGENTS.md guidelines. Check for:\n\n1. Commit message format (subject line, body, tags)\n2. License/copyright compliance\n3. C coding style issues\n4. API and documentation requirements\n5. Any other guideline violations\n\nProvide feedback organized by severity level.\n\n--- PATCH CONTENT ---\n"
        },
        {
            "role": "user",
            "content": $patch_content
        }
    ]
}
EOF
}

# Build request for Google Gemini API
build_google_request() {
    local agents_content="$1"
    local patch_content="$2"
    local patch_name="$3"

    cat <<EOF
{
    "contents": [
        {
            "role": "user",
            "parts": [
                {
                    "text": "You are an expert DPDK code reviewer. Analyze patches for compliance with DPDK coding standards and contribution guidelines. Provide clear, actionable feedback organized by severity (Error, Warning, Info) as defined in the guidelines.\n\nHere are the DPDK review guidelines:\n\n"
                }
            ]
        },
        {
            "role": "user",
            "parts": [
                {
                    "text": $agents_content
                }
            ]
        },
        {
            "role": "user",
            "parts": [
                {
                    "text": "Please review the following DPDK patch file '$patch_name' against the AGENTS.md guidelines. Check for:\n\n1. Commit message format (subject line, body, tags)\n2. License/copyright compliance\n3. C coding style issues\n4. API and documentation requirements\n5. Any other guideline violations\n\nProvide feedback organized by severity level.\n\n--- PATCH CONTENT ---\n"
                }
            ]
        },
        {
            "role": "user",
            "parts": [
                {
                    "text": $patch_content
                }
            ]
        }
    ],
    "generationConfig": {
        "maxOutputTokens": $MAX_TOKENS
    }
}
EOF
}

# Make API request for Anthropic
call_anthropic_api() {
    local request="$1"
    local api_key="$2"

    REQUEST_FILE=$(mktemp)
    echo "$request" > "$REQUEST_FILE"

    curl -s "${API_ENDPOINTS[anthropic]}" \
        -H "content-type: application/json" \
        -H "x-api-key: $api_key" \
        -H "anthropic-version: 2023-06-01" \
        -d "@$REQUEST_FILE"
}

# Make API request for OpenAI
call_openai_api() {
    local request="$1"
    local api_key="$2"

    REQUEST_FILE=$(mktemp)
    echo "$request" > "$REQUEST_FILE"

    curl -s "${API_ENDPOINTS[openai]}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $api_key" \
        -d "@$REQUEST_FILE"
}

# Make API request for xAI (Grok)
call_xai_api() {
    local request="$1"
    local api_key="$2"

    REQUEST_FILE=$(mktemp)
    echo "$request" > "$REQUEST_FILE"

    curl -s "${API_ENDPOINTS[xai]}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $api_key" \
        -d "@$REQUEST_FILE"
}

# Make API request for Google Gemini
call_google_api() {
    local request="$1"
    local api_key="$2"
    local model="$3"

    REQUEST_FILE=$(mktemp)
    echo "$request" > "$REQUEST_FILE"

    curl -s "${API_ENDPOINTS[google]}/${model}:generateContent?key=${api_key}" \
        -H "Content-Type: application/json" \
        -d "@$REQUEST_FILE"
}

# Extract response text from Anthropic response
extract_anthropic_response() {
    python3 -c "
import json
import sys
data = json.load(sys.stdin)
if 'error' in data:
    err = data['error']
    print(f\"Error type: {err.get('type', 'unknown')}\", file=sys.stderr)
    print(f\"Error message: {err.get('message', 'unknown')}\", file=sys.stderr)
    sys.exit(1)
for block in data.get('content', []):
    if block.get('type') == 'text':
        print(block.get('text', ''))
"
}

# Extract response text from OpenAI/xAI response
extract_openai_response() {
    python3 -c "
import json
import sys
data = json.load(sys.stdin)
if 'error' in data:
    err = data['error']
    print(f\"Error type: {err.get('type', 'unknown')}\", file=sys.stderr)
    print(f\"Error message: {err.get('message', 'unknown')}\", file=sys.stderr)
    print(f\"Error code: {err.get('code', 'unknown')}\", file=sys.stderr)
    sys.exit(1)
choices = data.get('choices', [])
if choices:
    message = choices[0].get('message', {})
    print(message.get('content', ''))
else:
    print('No response content received', file=sys.stderr)
"
}

# Extract response text from Google Gemini response
extract_google_response() {
    python3 -c "
import json
import sys
data = json.load(sys.stdin)
if 'error' in data:
    err = data['error']
    print(f\"Error code: {err.get('code', 'unknown')}\", file=sys.stderr)
    print(f\"Error message: {err.get('message', 'unknown')}\", file=sys.stderr)
    print(f\"Error status: {err.get('status', 'unknown')}\", file=sys.stderr)
    sys.exit(1)
candidates = data.get('candidates', [])
if candidates:
    content = candidates[0].get('content', {})
    parts = content.get('parts', [])
    for part in parts:
        print(part.get('text', ''))
else:
    print('No response candidates received', file=sys.stderr)
"
}

# Show verbose info for Anthropic
show_anthropic_verbose() {
    python3 -c "
import json
import sys
data = json.load(sys.stdin)
usage = data.get('usage', {})
print(f\"Input tokens: {usage.get('input_tokens', 'N/A')}\")
print(f\"Cache creation: {usage.get('cache_creation_input_tokens', 0)}\")
print(f\"Cache read: {usage.get('cache_read_input_tokens', 0)}\")
print(f\"Output tokens: {usage.get('output_tokens', 'N/A')}\")
"
}

# Show verbose info for OpenAI/xAI
show_openai_verbose() {
    python3 -c "
import json
import sys
data = json.load(sys.stdin)
usage = data.get('usage', {})
print(f\"Prompt tokens: {usage.get('prompt_tokens', 'N/A')}\")
print(f\"Completion tokens: {usage.get('completion_tokens', 'N/A')}\")
print(f\"Total tokens: {usage.get('total_tokens', 'N/A')}\")
"
}

# Show verbose info for Google
show_google_verbose() {
    python3 -c "
import json
import sys
data = json.load(sys.stdin)
usage = data.get('usageMetadata', {})
print(f\"Prompt tokens: {usage.get('promptTokenCount', 'N/A')}\")
print(f\"Output tokens: {usage.get('candidatesTokenCount', 'N/A')}\")
print(f\"Total tokens: {usage.get('totalTokenCount', 'N/A')}\")
"
}

# Parse command line options
VERBOSE=0
MODEL=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--provider)
            PROVIDER="$2"
            shift 2
            ;;
        -a|--agents)
            AGENTS_FILE="$2"
            shift 2
            ;;
        -m|--model)
            MODEL="$2"
            shift 2
            ;;
        -t|--tokens)
            MAX_TOKENS="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -l|--list-providers)
            list_providers
            ;;
        -h|--help)
            usage 0
            ;;
        -*)
            error "Unknown option: $1"
            ;;
        *)
            break
            ;;
    esac
done

# Validate provider
if [[ ! -v "DEFAULT_MODELS[$PROVIDER]" ]]; then
    error "Unknown provider: $PROVIDER. Use -l to list available providers."
fi

# Set default model if not specified
if [[ -z "$MODEL" ]]; then
    MODEL="${DEFAULT_MODELS[$PROVIDER]}"
fi

# Check for required arguments
if [[ $# -lt 1 ]]; then
    echo "Error: No patch file specified" >&2
    usage 1
fi

PATCH_FILE="$1"

# Get the API key variable name and check it's set
API_KEY_VAR="${API_KEY_VARS[$PROVIDER]}"
API_KEY="${!API_KEY_VAR}"

if [[ -z "$API_KEY" ]]; then
    error "$API_KEY_VAR environment variable not set"
fi

# Validate files exist
if [[ ! -f "$AGENTS_FILE" ]]; then
    error "AGENTS.md not found: $AGENTS_FILE"
fi

if [[ ! -f "$PATCH_FILE" ]]; then
    error "Patch file not found: $PATCH_FILE"
fi

# Read file contents
AGENTS_CONTENT=$(read_json_escaped "$AGENTS_FILE")
PATCH_CONTENT=$(read_json_escaped "$PATCH_FILE")
PATCH_BASENAME=$(basename "$PATCH_FILE")

if [[ $VERBOSE -eq 1 ]]; then
    echo "=== Request ===" >&2
    echo "Provider: $PROVIDER" >&2
    echo "Model: $MODEL" >&2
    echo "AGENTS file: $AGENTS_FILE" >&2
    echo "Patch file: $PATCH_FILE" >&2
    echo "===============" >&2
fi

# Build and send request based on provider
case "$PROVIDER" in
    anthropic)
        REQUEST=$(build_anthropic_request "$MODEL" "$MAX_TOKENS" "$AGENTS_CONTENT" "$PATCH_CONTENT" "$PATCH_BASENAME")
        RESPONSE=$(call_anthropic_api "$REQUEST" "$API_KEY")

        if [[ $VERBOSE -eq 1 ]]; then
            echo "=== Token Usage ===" >&2
            echo "$RESPONSE" | show_anthropic_verbose >&2
            echo "===================" >&2
        fi

        echo "=== Patch Review: $PATCH_BASENAME (via Claude) ==="
        echo "$RESPONSE" | extract_anthropic_response
        ;;

    openai)
        REQUEST=$(build_openai_request "$MODEL" "$MAX_TOKENS" "$AGENTS_CONTENT" "$PATCH_CONTENT" "$PATCH_BASENAME")
        RESPONSE=$(call_openai_api "$REQUEST" "$API_KEY")

        if [[ $VERBOSE -eq 1 ]]; then
            echo "=== Token Usage ===" >&2
            echo "$RESPONSE" | show_openai_verbose >&2
            echo "===================" >&2
        fi

        echo "=== Patch Review: $PATCH_BASENAME (via ChatGPT) ==="
        echo "$RESPONSE" | extract_openai_response
        ;;

    xai)
        REQUEST=$(build_openai_request "$MODEL" "$MAX_TOKENS" "$AGENTS_CONTENT" "$PATCH_CONTENT" "$PATCH_BASENAME")
        RESPONSE=$(call_xai_api "$REQUEST" "$API_KEY")

        if [[ $VERBOSE -eq 1 ]]; then
            echo "=== Token Usage ===" >&2
            echo "$RESPONSE" | show_openai_verbose >&2
            echo "===================" >&2
        fi

        echo "=== Patch Review: $PATCH_BASENAME (via Grok) ==="
        echo "$RESPONSE" | extract_openai_response
        ;;

    google)
        REQUEST=$(build_google_request "$AGENTS_CONTENT" "$PATCH_CONTENT" "$PATCH_BASENAME")
        RESPONSE=$(call_google_api "$REQUEST" "$API_KEY" "$MODEL")

        if [[ $VERBOSE -eq 1 ]]; then
            echo "=== Token Usage ===" >&2
            echo "$RESPONSE" | show_google_verbose >&2
            echo "===================" >&2
        fi

        echo "=== Patch Review: $PATCH_BASENAME (via Gemini) ==="
        echo "$RESPONSE" | extract_google_response
        ;;
esac
