#!/usr/bin/env bash
# Reset rate limiting for a specific source
# Usage: ./reset-rate-limit.sh <source_id>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="${RATE_LIMIT_STATE_FILE:-$HOME/.claude/hooks/rate-limit-state.json}"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <source_id>"
    echo ""
    echo "Reset rate limiting for a specific source."
    echo ""
    echo "Examples:"
    echo "  $0 cli:ren@laptop:pts/2"
    echo "  $0 telegram:chat_12345"
    echo "  $0 --list    # List all sources"
    exit 1
fi

if [[ "$1" == "--list" ]]; then
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "State file not found: $STATE_FILE"
        exit 0
    fi

    python3 -c "
import json, sys
from datetime import datetime, timezone

try:
    state = json.load(open('$STATE_FILE'))
    sources = state.get('sources', {})
    if not sources:
        print('No sources in state file')
        sys.exit(0)

    print(f'{"Source ID":<40} {"Blocked Until":<25} {"Level":<6} {"Violations"}')
    print('-' * 100)
    for sid, data in sources.items():
        blocked = data.get('blocked_until', 'None')
        level = data.get('backoff_level', 0)
        violations = data.get('violation_count', 0)

        # Check if still blocked
        if blocked and blocked != 'None':
            try:
                block_time = datetime.fromisoformat(blocked.replace('Z', '+00:00'))
                now = datetime.now(timezone.utc)
                if block_time <= now:
                    blocked = 'Expired'
            except:
                pass

        print(f'{sid:<40} {blocked:<25} {level:<6} {violations}')
except FileNotFoundError:
    print('State file not found: $STATE_FILE')
"
    exit 0
fi

SOURCE_ID="$1"

# Lock and update state file
python3 -c "
import json, sys, os, tempfile

state_file = '$STATE_FILE'
source_id = '$SOURCE_ID'

if not os.path.exists(state_file):
    print(f'State file not found: {state_file}')
    sys.exit(1)

# Lock and read state
state = json.load(open(state_file))
sources = state.get('sources', {})

if source_id not in sources:
    print(f'Source not found: {source_id}')
    print(f'Available sources: {list(sources.keys())}')
    sys.exit(1)

# Reset source
sources[source_id] = {
    'source_id': source_id,
    'source_type': sources[source_id].get('source_type', 'unknown'),
    'violation_count': 0,
    'backoff_level': 0,
    'blocked_until': None,
    'last_violation': None,
    'first_violation': None,
    'last_threat_ids': [],
    'last_severities': []
}

# Write atomically
with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=os.path.dirname(state_file)) as tmp:
    json.dump(state, tmp, indent=2)
    tmp_name = tmp.name

os.rename(tmp_name, state_file)
print(f'Reset rate limit for: {source_id}')
"
