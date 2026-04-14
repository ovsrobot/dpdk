#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

# Compare DPDK patch reviews across multiple AI providers
# Runs analyze-patch.py with each available provider

set -o pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
ANALYZE_SCRIPT="${SCRIPT_DIR}/analyze-patch.py"
AGENTS_FILE="AGENTS.md"
OUTPUT_DIR=""
PROVIDERS=""
FORMAT="text"
VERBOSE=""
EXTRA_ARGS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <patch-file>

Compare DPDK patch reviews across multiple AI providers.

Options:
    -a, --agents FILE      Path to AGENTS.md file (default: AGENTS.md)
    -o, --output DIR       Save individual reviews to directory
    -p, --providers LIST   Comma-separated list of providers to use
                           (default: all providers with API keys set)
    -f, --format FORMAT    Output format: text, markdown, html, json
                           (default: text)
    -t, --tokens N         Max tokens for response
    -D, --date DATE        Review date context (YYYY-MM-DD)
    -r, --release VERSION  Target DPDK release (e.g., 24.11, 23.11-lts)
    --split-patches        Split mbox into individual patches
    --patch-range N-M      Review only patches N through M
    --large-file MODE      Handle large files: error, truncate, chunk,
                           commits-only, summary
    --max-tokens N         Max input tokens
    -v, --verbose          Show verbose output from each provider
    -h, --help             Show this help message

Environment Variables:
    Set API keys for providers you want to use:
    ANTHROPIC_API_KEY, OPENAI_API_KEY, XAI_API_KEY, GOOGLE_API_KEY

Examples:
    $(basename "$0") my-patch.patch
    $(basename "$0") -p anthropic,openai my-patch.patch
    $(basename "$0") -o ./reviews -f markdown my-patch.patch
    $(basename "$0") -r 24.11 --split-patches series.mbox
EOF
    exit "${1:-0}"
}

error() {
    echo "Error: $1" >&2
    exit 1
}

# Check which providers have API keys configured
get_available_providers() {
    local available=""

    [[ -n "$ANTHROPIC_API_KEY" ]] && available="${available}anthropic,"
    [[ -n "$OPENAI_API_KEY" ]] && available="${available}openai,"
    [[ -n "$XAI_API_KEY" ]] && available="${available}xai,"
    [[ -n "$GOOGLE_API_KEY" ]] && available="${available}google,"

    # Remove trailing comma
    echo "${available%,}"
}

# Get file extension for format
get_extension() {
    case "$1" in
        text)     echo "txt" ;;
        markdown) echo "md" ;;
        html)     echo "html" ;;
        json)     echo "json" ;;
        *)        echo "txt" ;;
    esac
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--agents)
            [[ -z "${2:-}" || "$2" == -* ]] && error "$1 requires an argument"
            AGENTS_FILE="$2"
            shift 2
            ;;
        -o|--output)
            [[ -z "${2:-}" || "$2" == -* ]] && error "$1 requires an argument"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -p|--providers)
            [[ -z "${2:-}" || "$2" == -* ]] && error "$1 requires an argument"
            PROVIDERS="$2"
            shift 2
            ;;
        -f|--format)
            [[ -z "${2:-}" || "$2" == -* ]] && error "$1 requires an argument"
            FORMAT="$2"
            shift 2
            ;;
        -t|--tokens)
            [[ -z "${2:-}" || "$2" == -* ]] && error "$1 requires an argument"
            EXTRA_ARGS+=("-t" "$2")
            shift 2
            ;;
        -D|--date)
            [[ -z "${2:-}" || "$2" == -* ]] && error "$1 requires an argument"
            EXTRA_ARGS+=("-D" "$2")
            shift 2
            ;;
        -r|--release)
            [[ -z "${2:-}" || "$2" == -* ]] && error "$1 requires an argument"
            EXTRA_ARGS+=("-r" "$2")
            shift 2
            ;;
        --split-patches)
            EXTRA_ARGS+=("--split-patches")
            shift
            ;;
        --patch-range)
            [[ -z "${2:-}" || "$2" == -* ]] && error "$1 requires an argument"
            EXTRA_ARGS+=("--patch-range" "$2")
            shift 2
            ;;
        --large-file)
            [[ -z "${2:-}" || "$2" == -* ]] && error "$1 requires an argument"
            EXTRA_ARGS+=("--large-file" "$2")
            shift 2
            ;;
        --large-file=*)
            EXTRA_ARGS+=("$1")
            shift
            ;;
        --max-tokens)
            [[ -z "${2:-}" || "$2" == -* ]] && error "$1 requires an argument"
            EXTRA_ARGS+=("--max-tokens" "$2")
            shift 2
            ;;
        -v|--verbose)
            VERBOSE="-v"
            shift
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

# Check for required arguments
if [[ $# -lt 1 ]]; then
    echo "Error: No patch file specified" >&2
    usage 1
fi

PATCH_FILE="$1"

if [[ ! -f "$PATCH_FILE" ]]; then
    error "Patch file not found: $PATCH_FILE"
fi

if [[ ! -f "$ANALYZE_SCRIPT" ]]; then
    error "analyze-patch.py not found: $ANALYZE_SCRIPT"
fi

if [[ ! -f "$AGENTS_FILE" ]]; then
    error "AGENTS.md not found: $AGENTS_FILE"
fi

# Validate format
case "$FORMAT" in
    text|markdown|html|json) ;;
    *) error "Invalid format: $FORMAT (must be text, markdown, html, or json)" ;;
esac

# Get providers to use
if [[ -z "$PROVIDERS" ]]; then
    PROVIDERS=$(get_available_providers)
fi

if [[ -z "$PROVIDERS" ]]; then
    error "No API keys configured. Set at least one of: "\
"ANTHROPIC_API_KEY, OPENAI_API_KEY, XAI_API_KEY, GOOGLE_API_KEY"
fi

# Create output directory if specified
if [[ -n "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR"
fi

PATCH_BASENAME=$(basename "$PATCH_FILE")
PATCH_STEM="${PATCH_BASENAME%.*}"
EXT=$(get_extension "$FORMAT")

echo "Reviewing patch: $PATCH_BASENAME"
echo "Providers: $PROVIDERS"
echo "Format: $FORMAT"
echo "========================================"
echo ""

# Run review for each provider, continue on failure
IFS=',' read -ra PROVIDER_LIST <<< "$PROVIDERS"
failures=0
for provider in "${PROVIDER_LIST[@]}"; do
    echo ">>> Running review with: $provider"
    echo ""

    if [[ -n "$OUTPUT_DIR" ]]; then
        OUTPUT_FILE="${OUTPUT_DIR}/${PATCH_STEM}-${provider}.${EXT}"
        if python3 "$ANALYZE_SCRIPT" \
            -p "$provider" \
            -a "$AGENTS_FILE" \
            -f "$FORMAT" \
            ${VERBOSE:+"$VERBOSE"} \
            "${EXTRA_ARGS[@]}" \
            "$PATCH_FILE" | tee "$OUTPUT_FILE"; then
            echo ""
            echo "Saved to: $OUTPUT_FILE"
        else
            echo "FAILED: $provider review failed" >&2
            rm -f "$OUTPUT_FILE"
            ((failures++)) || true
        fi
    else
        if ! python3 "$ANALYZE_SCRIPT" \
            -p "$provider" \
            -a "$AGENTS_FILE" \
            -f "$FORMAT" \
            ${VERBOSE:+"$VERBOSE"} \
            "${EXTRA_ARGS[@]}" \
            "$PATCH_FILE"; then
            echo "FAILED: $provider review failed" >&2
            ((failures++)) || true
        fi
    fi

    echo ""
    echo "========================================"
    echo ""
done

echo "Review comparison complete."

if [[ -n "$OUTPUT_DIR" ]]; then
    echo "All reviews saved to: $OUTPUT_DIR"
fi

if [[ $failures -gt 0 ]]; then
    echo "$failures provider(s) failed." >&2
    exit 1
fi
