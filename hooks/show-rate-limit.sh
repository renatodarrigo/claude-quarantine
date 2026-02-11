#!/usr/bin/env bash
# Show current rate limit status for this source
# Usage: ./show-rate-limit.sh [source_id]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the injection-guard script to access generate_source_id function
# Extract just the function we need without executing main
generate_source_id() {
    # Priority 1: Explicit source ID from environment
    if [[ -n "${CLAUDE_SOURCE_ID:-}" ]]; then
        printf '%s' "$CLAUDE_SOURCE_ID"
        return 0
    fi

    # Priority 2: Auto-detection from environment
    local source_type="" source_id=""

    # Check for SSH session
    if [[ -n "${SSH_CLIENT:-}" ]] || [[ -n "${SSH_CONNECTION:-}" ]]; then
        local remote_ip
        remote_ip=$(echo "${SSH_CLIENT:-${SSH_CONNECTION:-}}" | awk '{print $1}')
        source_type="ssh"
        source_id="${USER}@${remote_ip}"
    # Check for tmux session
    elif [[ -n "${TMUX:-}" ]]; then
        local tmux_session
        tmux_session=$(tmux display-message -p '#S' 2>/dev/null || echo "unknown")
        source_type="tmux"
        source_id="${USER}:${tmux_session}"
    # Check for screen session
    elif [[ -n "${STY:-}" ]]; then
        source_type="screen"
        source_id="${USER}:${STY}"
    # Local terminal
    elif [[ -n "${TTY:-}" ]] || tty &>/dev/null; then
        local tty_name
        tty_name=$(tty 2>/dev/null | sed 's|/dev/||' || echo "notty")
        source_type="cli"
        source_id="${USER}@${HOSTNAME}:${tty_name}"
    fi

    # Return detected source or unknown fallback
    if [[ -n "$source_id" ]]; then
        printf '%s:%s' "$source_type" "$source_id"
    else
        # Priority 3: Unknown fallback
        printf 'unknown:%s' "$(date +%s)"
    fi
}

# Use provided source ID or auto-detect
SOURCE_ID="${1:-$(generate_source_id)}"
STATE_FILE="${RATE_LIMIT_STATE_FILE:-$HOME/.claude/hooks/rate-limit-state.json}"

if [[ ! -f "$STATE_FILE" ]]; then
    echo "No rate limiting state found. You're not blocked."
    exit 0
fi

python3 -c "
import json, sys
from datetime import datetime, timezone

state = json.load(open('$STATE_FILE'))
sources = state.get('sources', {})
source_id = '$SOURCE_ID'

if source_id not in sources:
    print(f'Source ID: {source_id}')
    print('Status: Not tracked (no violations)')
    sys.exit(0)

src = sources[source_id]
blocked_until = src.get('blocked_until')
now = datetime.now(timezone.utc)

print(f'Source ID: {source_id}')
print(f'Violation count: {src.get(\"violation_count\", 0)}')
print(f'Backoff level: {src.get(\"backoff_level\", 0)}')

if blocked_until:
    try:
        block_time = datetime.fromisoformat(blocked_until.replace('Z', '+00:00'))
        if block_time > now:
            remaining = int((block_time - now).total_seconds())
            mins = remaining // 60
            secs = remaining % 60
            print(f'Status: BLOCKED for {mins}m {secs}s')
            print(f'Blocked until: {blocked_until}')
        else:
            print('Status: Clean (block expired)')
    except (ValueError, AttributeError):
        print('Status: Clean (invalid timestamp)')
else:
    print('Status: Clean')

if 'last_violation' in src and src['last_violation']:
    print(f'Last violation: {src[\"last_violation\"]}')

if 'last_threat_ids' in src and src['last_threat_ids']:
    print(f'Recent threats: {src[\"last_threat_ids\"][-3:]}')
"
