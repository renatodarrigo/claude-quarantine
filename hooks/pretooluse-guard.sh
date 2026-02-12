#!/usr/bin/env bash
# claude-guard — Layer 0: Pre-Tool-Use URL Blocklist
# PreToolUse hook for Claude Code
#
# Checks URLs against a blocklist BEFORE tool execution.
# Pure bash — no python3, no external dependencies, must be fast (~10ms).
#
# Exit codes:
#   0 — allowed (URL not in blocklist or no URL found)
#   2 — blocked (URL matches blocklist entry)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${GUARD_CONFIG:-$SCRIPT_DIR/injection-guard.conf}"

# Defaults
ENABLE_LAYER0="${ENABLE_LAYER0:-true}"
BLOCKLIST_FILE="${BLOCKLIST_FILE:-$SCRIPT_DIR/blocklist.conf}"
BLOCKLIST_REMOTE_URL="${BLOCKLIST_REMOTE_URL:-}"
BLOCKLIST_REMOTE_CACHE_TTL="${BLOCKLIST_REMOTE_CACHE_TTL:-86400}"

# Load config (lightweight — only reads the keys we need)
if [[ -f "$CONF_FILE" ]]; then
    while IFS='=' read -r key value; do
        key="${key%%#*}"; key="${key// /}"
        value="${value%%#*}"; value="${value// /}"
        case "$key" in
            ENABLE_LAYER0)              ENABLE_LAYER0="${ENABLE_LAYER0:-$value}" ;;
            BLOCKLIST_FILE)             BLOCKLIST_FILE="${BLOCKLIST_FILE:-${value/#\~/$HOME}}" ;;
            BLOCKLIST_REMOTE_URL)       BLOCKLIST_REMOTE_URL="${BLOCKLIST_REMOTE_URL:-$value}" ;;
            BLOCKLIST_REMOTE_CACHE_TTL) BLOCKLIST_REMOTE_CACHE_TTL="${BLOCKLIST_REMOTE_CACHE_TTL:-$value}" ;;
        esac
    done < "$CONF_FILE"
fi

# Expand tilde
BLOCKLIST_FILE="${BLOCKLIST_FILE/#\~/$HOME}"

# Early exit if disabled
if [[ "$ENABLE_LAYER0" != "true" ]]; then
    echo '{}'
    exit 0
fi

# Read input JSON from stdin
INPUT=$(cat)
if [[ -z "$INPUT" ]]; then
    echo '{}'
    exit 0
fi

# Extract tool name — fast JSON parsing without python3
TOOL_NAME=""
if [[ "$INPUT" =~ \"tool_name\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
    TOOL_NAME="${BASH_REMATCH[1]}"
fi

# Extract URLs from input
declare -a URLS=()

# For WebFetch: extract tool_input.url
if [[ "$INPUT" =~ \"url\"[[:space:]]*:[[:space:]]*\"(https?://[^\"]+)\" ]]; then
    URLS+=("${BASH_REMATCH[1]}")
fi

# For Bash: extract URLs from command text
if [[ "$TOOL_NAME" == "Bash" ]]; then
    # Extract command from tool_input
    if [[ "$INPUT" =~ \"command\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
        local_cmd="${BASH_REMATCH[1]}"
        # Regex-extract URLs from the command
        while [[ "$local_cmd" =~ (https?://[^[:space:]\"\'\\]+) ]]; do
            URLS+=("${BASH_REMATCH[1]}")
            local_cmd="${local_cmd#*${BASH_REMATCH[1]}}"
        done
    fi
fi

# If no URLs found, allow
if [[ ${#URLS[@]} -eq 0 ]]; then
    echo '{}'
    exit 0
fi

# Load blocklist patterns
declare -a BLOCKLIST=()

load_blocklist_file() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    while IFS= read -r line; do
        line="${line%%#*}"     # strip comments
        line="${line// /}"     # strip spaces
        [[ -z "$line" ]] && continue
        BLOCKLIST+=("$line")
    done < "$file"
}

# Load local blocklist
load_blocklist_file "$BLOCKLIST_FILE"

# Load remote blocklist (cached)
if [[ -n "$BLOCKLIST_REMOTE_URL" ]]; then
    CACHE_FILE="${BLOCKLIST_FILE%.conf}-remote-cache.txt"
    SHOULD_FETCH=false

    if [[ ! -f "$CACHE_FILE" ]]; then
        SHOULD_FETCH=true
    else
        # Check if cache is stale
        CACHE_AGE=$(( $(date +%s) - $(stat -c%Y "$CACHE_FILE" 2>/dev/null || stat -f%m "$CACHE_FILE" 2>/dev/null || echo 0) ))
        if (( CACHE_AGE > BLOCKLIST_REMOTE_CACHE_TTL )); then
            SHOULD_FETCH=true
        fi
    fi

    if [[ "$SHOULD_FETCH" == "true" ]]; then
        # Fetch with 5s timeout, fail silently
        if command -v timeout &>/dev/null; then
            timeout 5s curl -fsSL "$BLOCKLIST_REMOTE_URL" > "$CACHE_FILE" 2>/dev/null || true
        elif command -v gtimeout &>/dev/null; then
            gtimeout 5s curl -fsSL "$BLOCKLIST_REMOTE_URL" > "$CACHE_FILE" 2>/dev/null || true
        else
            curl -fsSL --connect-timeout 5 "$BLOCKLIST_REMOTE_URL" > "$CACHE_FILE" 2>/dev/null || true
        fi
    fi

    load_blocklist_file "$CACHE_FILE"
fi

# If no blocklist entries, allow
if [[ ${#BLOCKLIST[@]} -eq 0 ]]; then
    echo '{}'
    exit 0
fi

# Check each URL against blocklist
check_url_blocked() {
    local url="$1"
    local host=""

    # Extract host from URL
    if [[ "$url" =~ ^https?://([^/]+) ]]; then
        host="${BASH_REMATCH[1]}"
    fi
    [[ -z "$host" ]] && return 1

    for pattern in "${BLOCKLIST[@]}"; do
        # Exact URL match
        if [[ "$url" == "$pattern" ]]; then
            return 0
        fi

        # Wildcard domain: *.malicious.com
        if [[ "$pattern" == \*.* ]]; then
            local suffix="${pattern#\*}"
            if [[ "$host" == *"$suffix" ]] || [[ ".$host" == *"$suffix" ]]; then
                return 0
            fi
        fi

        # Exact host match
        if [[ "$host" == "$pattern" ]]; then
            return 0
        fi
    done

    return 1
}

for url in "${URLS[@]}"; do
    if check_url_blocked "$url"; then
        # Extract just the host for the message
        blocked_host=""
        if [[ "$url" =~ ^https?://([^/]+) ]]; then
            blocked_host="${BASH_REMATCH[1]}"
        fi

        # JSON-escape the message (simple — no python3)
        msg="BLOCKED: URL $blocked_host is on the blocklist. Tool execution prevented."
        msg="${msg//\\/\\\\}"
        msg="${msg//\"/\\\"}"

        printf '{"systemMessage":"%s","blocked":true}\n' "$msg"
        exit 2
    fi
done

echo '{}'
exit 0
