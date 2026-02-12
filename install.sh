#!/usr/bin/env bash
# claude-guard installer
# Copies hooks and MCP server to ~/.claude/ (user) or .claude/ (project) and configures settings.json
#
# Usage:
#   ./install.sh                       # Install to ~/.claude/ (user-level, global)
#   ./install.sh --project=~/myapp     # Install to ~/myapp/.claude/ (project-level)
#
# One-liner install:
#   curl -fsSL https://raw.githubusercontent.com/renatodarrigo/claude-guard/main/install.sh | bash
set -euo pipefail

INSTALL_MODE="user"
PROJECT_DIR=""
CLEANUP_TEMP=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project=*)
            INSTALL_MODE="project"
            PROJECT_DIR="${1#--project=}"; shift ;;
        --project)
            echo "Error: --project requires a path, e.g. --project=~/myapp" >&2
            exit 1
            ;;
        --help|-h)
            echo "USAGE: ./install.sh [OPTIONS]"
            echo ""
            echo "OPTIONS:"
            echo "  --project=DIR    Install to DIR/.claude/ (project-level, committable)"
            echo "  --help           Show this help message"
            echo ""
            echo "EXAMPLES:"
            echo "  ./install.sh                       # User-level: ~/.claude/"
            echo "  ./install.sh --project=~/myapp     # Project-level: ~/myapp/.claude/"
            exit 0
            ;;
        *)
            echo "Error: Unknown option '$1'" >&2
            echo "Run './install.sh --help' for usage." >&2
            exit 1
            ;;
    esac
done

if [[ "$INSTALL_MODE" == "project" ]]; then
    # Expand ~ manually (not expanded inside quotes)
    PROJECT_DIR="${PROJECT_DIR/#\~/$HOME}"
    if [[ ! -d "$PROJECT_DIR" ]]; then
        echo "Error: directory '$PROJECT_DIR' does not exist" >&2
        exit 1
    fi
    PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"
    CLAUDE_DIR="$PROJECT_DIR/.claude"
else
    CLAUDE_DIR="$HOME/.claude"
fi

# Detect if running from a cloned repo or piped from curl
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "bash" && -f "${BASH_SOURCE[0]}" ]]; then
    REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    REPO_DIR=""
fi

# If not in the repo (piped install), clone to a temp directory
if [[ -z "$REPO_DIR" || ! -f "$REPO_DIR/hooks/injection-guard.sh" ]]; then
    TEMP_DIR=$(mktemp -d)
    CLEANUP_TEMP=true
    echo "Downloading claude-guard..."
    if ! git clone --depth 1 https://github.com/renatodarrigo/claude-guard.git "$TEMP_DIR" 2>/dev/null; then
        echo "Error: Failed to clone repository. Make sure git is installed."
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    REPO_DIR="$TEMP_DIR"
    echo ""
fi
HOOKS_DIR="$CLAUDE_DIR/hooks"
MCP_DIR="$CLAUDE_DIR/mcp/claude-guard"

echo "claude-guard installer"
echo "==========================="
if [[ "$INSTALL_MODE" == "project" ]]; then
    echo "Mode: project-level ($PROJECT_DIR/.claude/)"
else
    echo "Mode: user-level (~/.claude/)"
fi
echo ""

# --- Install skills ---
COMMANDS_DIR="$CLAUDE_DIR/commands"
echo "Installing skills to $COMMANDS_DIR..."
mkdir -p "$COMMANDS_DIR"
cp "$REPO_DIR/review-threats.md" "$COMMANDS_DIR/"
cp "$REPO_DIR/update-guard.md" "$COMMANDS_DIR/"
cp "$REPO_DIR/guard-stats.md" "$COMMANDS_DIR/"
cp "$REPO_DIR/test-pattern.md" "$COMMANDS_DIR/"
cp "$REPO_DIR/guard-config.md" "$COMMANDS_DIR/"

# --- Install hooks ---
echo "Installing hooks to $HOOKS_DIR..."
mkdir -p "$HOOKS_DIR"
cp "$REPO_DIR/hooks/injection-guard.sh" "$HOOKS_DIR/"
cp "$REPO_DIR/hooks/injection-patterns.conf" "$HOOKS_DIR/"
cp "$REPO_DIR/hooks/pretooluse-guard.sh" "$HOOKS_DIR/"
cp "$REPO_DIR/hooks/guard-lib-rotation.sh" "$HOOKS_DIR/"
cp "$REPO_DIR/hooks/guard-lib-allowlist.sh" "$HOOKS_DIR/"
cp "$REPO_DIR/hooks/guard-lib-cache.sh" "$HOOKS_DIR/"
cp "$REPO_DIR/hooks/file-patterns.conf" "$HOOKS_DIR/"
chmod +x "$HOOKS_DIR/injection-guard.sh"
chmod +x "$HOOKS_DIR/pretooluse-guard.sh"

# Install config-only files only if they don't exist (don't overwrite user config)
for conf_file in injection-guard.conf allowlist.conf blocklist.conf pattern-overrides.conf; do
    if [[ ! -f "$HOOKS_DIR/$conf_file" ]]; then
        cp "$REPO_DIR/hooks/$conf_file" "$HOOKS_DIR/"
        # For project installs, update paths to use project-relative
        if [[ "$INSTALL_MODE" == "project" ]]; then
            sed -i.bak 's|~/.claude/hooks/|.claude/hooks/|g' "$HOOKS_DIR/$conf_file"
            rm -f "$HOOKS_DIR/$conf_file.bak"
        fi
        echo "  Created $conf_file"
    else
        echo "  $conf_file already exists (kept existing)"
    fi
done

# Install admin tools
for admin_script in reset-rate-limit.sh show-rate-limit.sh; do
    if [[ -f "$REPO_DIR/hooks/$admin_script" ]]; then
        cp "$REPO_DIR/hooks/$admin_script" "$HOOKS_DIR/"
        chmod +x "$HOOKS_DIR/$admin_script"
    fi
done

# Create quarantine directory
mkdir -p "$HOOKS_DIR/quarantine"

# --- Create .gitignore for project installs ---
if [[ "$INSTALL_MODE" == "project" ]]; then
    cat > "$CLAUDE_DIR/.gitignore" <<'GITIGNORE'
settings.local.json
hooks/injection-guard.log
hooks/injection-guard.log.*
hooks/confirmed-threats.json
hooks/rate-limit-state.json
hooks/scan-cache.json
hooks/session-buffer.json
hooks/quarantine/
hooks/blocklist-remote-cache.txt
GITIGNORE
    echo "  Created $CLAUDE_DIR/.gitignore"
fi

# --- Install MCP server ---
echo "Installing MCP server to $MCP_DIR..."
mkdir -p "$MCP_DIR/src/tools"
cp "$REPO_DIR/mcp/package.json" "$MCP_DIR/"
cp "$REPO_DIR/mcp/tsconfig.json" "$MCP_DIR/"
cp "$REPO_DIR/mcp/src/"*.ts "$MCP_DIR/src/"
cp "$REPO_DIR/mcp/src/tools/"*.ts "$MCP_DIR/src/tools/"

echo "  Installing dependencies..."
(cd "$MCP_DIR" && npm install --silent 2>&1)

echo "  Building TypeScript..."
(cd "$MCP_DIR" && npx tsc 2>&1)

# --- Configure settings.json ---
SETTINGS_FILE="$CLAUDE_DIR/settings.json"
echo ""
echo "Configuring $SETTINGS_FILE..."

if [[ -f "$SETTINGS_FILE" ]]; then
    # Check if already configured
    if grep -q "injection-guard" "$SETTINGS_FILE" 2>/dev/null; then
        echo "  Hook already configured in settings.json (skipping)"
    else
        echo "  WARNING: settings.json exists but doesn't contain claude-guard config."
        echo "  You need to manually add the hook and MCP server configuration."
        echo "  See the README for the required settings.json entries."
    fi
else
    if [[ "$INSTALL_MODE" == "project" ]]; then
        cat > "$SETTINGS_FILE" <<'SETTINGS'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "WebFetch|Bash",
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/pretooluse-guard.sh",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "WebFetch|Bash|web_search|mcp__.*|Read|Grep",
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/injection-guard.sh",
            "timeout": 60
          }
        ]
      }
    ]
  },
  "mcpServers": {
    "claude-guard": {
      "command": "node",
      "args": [".claude/mcp/claude-guard/dist/index.js"],
      "env": {
        "GUARD_CONFIG": ".claude/hooks/injection-guard.conf",
        "GUARD_PATTERNS": ".claude/hooks/injection-patterns.conf",
        "GUARD_ALLOWLIST": ".claude/hooks/allowlist.conf"
      }
    }
  }
}
SETTINGS
    else
        cat > "$SETTINGS_FILE" <<'SETTINGS'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "WebFetch|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/pretooluse-guard.sh",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "WebFetch|Bash|web_search|mcp__.*|Read|Grep",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/injection-guard.sh",
            "timeout": 60
          }
        ]
      }
    ]
  },
  "mcpServers": {
    "claude-guard": {
      "command": "node",
      "args": ["~/.claude/mcp/claude-guard/dist/index.js"],
      "env": {
        "GUARD_CONFIG": "~/.claude/hooks/injection-guard.conf",
        "GUARD_PATTERNS": "~/.claude/hooks/injection-patterns.conf",
        "GUARD_ALLOWLIST": "~/.claude/hooks/allowlist.conf"
      }
    }
  }
}
SETTINGS
    fi
    echo "  Created settings.json with PreToolUse + PostToolUse hooks and MCP server config"
fi

# --- Write version marker ---
if [[ -f "$REPO_DIR/VERSION" ]]; then
    cp "$REPO_DIR/VERSION" "$CLAUDE_DIR/.guard-version"
fi

echo ""
VERSION_STR=""
if [[ -f "$CLAUDE_DIR/.guard-version" ]]; then
    VERSION_STR=$(cat "$CLAUDE_DIR/.guard-version" | tr -d '[:space:]')
fi
echo "Installation complete! ${VERSION_STR:+(v$VERSION_STR)}"
echo ""
echo "Layer 0 (URL Blocklist):   Active on WebFetch and Bash (PreToolUse)"
echo "Layer 1 (Pattern Scanner): Active on all WebFetch, Bash, web_search, and MCP tool results"
echo "Layer 3 (MCP Proxy):       Available as secure_fetch, secure_gh, secure_curl tools"
echo ""
echo "Configuration: $HOOKS_DIR/injection-guard.conf"
echo "Patterns:      $HOOKS_DIR/injection-patterns.conf"
echo "Allowlist:     $HOOKS_DIR/allowlist.conf"
echo "Blocklist:     $HOOKS_DIR/blocklist.conf"
echo "Logs:          $HOOKS_DIR/injection-guard.log"
echo ""
echo "Skills: /review-threats, /update-guard, /guard-stats, /test-pattern, /guard-config"
echo ""

if [[ "$INSTALL_MODE" == "project" ]]; then
    echo "Project configuration at $CLAUDE_DIR/"
    echo "Commit to git to share security config with your team."
else
    echo "Global configuration at $CLAUDE_DIR/"
    echo "Applies to all Claude Code sessions."
fi

# Clean up temp directory if we cloned
if [[ "$CLEANUP_TEMP" == "true" && -n "${TEMP_DIR:-}" ]]; then
    rm -rf "$TEMP_DIR"
fi
