#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

# Compare DPDK patch reviews across multiple AI providers
# Runs analyze-patch.sh with each available provider

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
ANALYZE_SCRIPT="${SCRIPT_DIR}/analyze-patch.sh"
AGENTS_FILE="AGENTS.md"
OUTPUT_DIR=""
PROVIDERS=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <patch-file>

Compare DPDK patch reviews across multiple AI providers.

Options:
    -a, --agents FILE      Path to AGENTS.md file (default: AGENTS.md)
    -o, --output DIR       Save individual reviews to directory
    -p, --providers LIST   Comma-separated list of providers to use
                           (default: all providers with API keys set)
    -v, --verbose          Show verbose output from each provider
    -h, --help             Show this help message

Environment Variables:
    Set API keys for providers you want to use:
    ANTHROPIC_API_KEY, OPENAI_API_KEY, XAI_API_KEY, GOOGLE_API_KEY

Examples:
    $(basename "$0") my-patch.patch
    $(basename "$0") -p anthropic,openai my-patch.patch
    $(basename "$0") -o ./reviews my-patch.patch
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

# Parse command line options
VERBOSE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--agents)
            AGENTS_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -p|--providers)
            PROVIDERS="$2"
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
    error "analyze-patch.sh not found: $ANALYZE_SCRIPT"
fi

# Get providers to use
if [[ -z "$PROVIDERS" ]]; then
    PROVIDERS=$(get_available_providers)
fi

if [[ -z "$PROVIDERS" ]]; then
    error "No API keys configured. Set at least one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, XAI_API_KEY, GOOGLE_API_KEY"
fi

# Create output directory if specified
if [[ -n "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR"
fi

PATCH_BASENAME=$(basename "$PATCH_FILE")
echo "Reviewing patch: $PATCH_BASENAME"
echo "Providers: $PROVIDERS"
echo "========================================"
echo ""

# Run review for each provider
IFS=',' read -ra PROVIDER_LIST <<< "$PROVIDERS"
for provider in "${PROVIDER_LIST[@]}"; do
    echo ">>> Running review with: $provider"
    echo ""

    if [[ -n "$OUTPUT_DIR" ]]; then
        OUTPUT_FILE="${OUTPUT_DIR}/${PATCH_BASENAME%.patch}-${provider}.txt"
        "$ANALYZE_SCRIPT" -p "$provider" -a "$AGENTS_FILE" $VERBOSE "$PATCH_FILE" | tee "$OUTPUT_FILE"
        echo ""
        echo "Saved to: $OUTPUT_FILE"
    else
        "$ANALYZE_SCRIPT" -p "$provider" -a "$AGENTS_FILE" $VERBOSE "$PATCH_FILE"
    fi

    echo ""
    echo "========================================"
    echo ""
done

echo "Review comparison complete."

if [[ -n "$OUTPUT_DIR" ]]; then
    echo "All reviews saved to: $OUTPUT_DIR"
fi
