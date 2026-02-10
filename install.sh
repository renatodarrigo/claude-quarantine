#!/usr/bin/env bash
# claude-quarantine installer
# Copies hooks and MCP server to ~/.claude/ (user) or .claude/ (project) and configures settings.json
#
# Usage:
#   ./install.sh              # Install to ~/.claude/ (user-level, global)
#   ./install.sh --project    # Install to .claude/ (project-level, committable)
#
# One-liner install:
#   curl -fsSL https://raw.githubusercontent.com/renatodarrigo/claude-quarantine/main/install.sh | bash
set -euo pipefail

INSTALL_MODE="user"
CLEANUP_TEMP=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project) INSTALL_MODE="project"; shift ;;
        --help|-h)
            echo "USAGE: ./install.sh [OPTIONS]"
            echo ""
            echo "OPTIONS:"
            echo "  --project    Install to .claude/ in current directory (project-level)"
            echo "  --help       Show this help message"
            echo ""
            echo "Default: Install to ~/.claude/ (user-level, applies to all sessions)"
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
    CLAUDE_DIR=".claude"
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
    echo "Downloading claude-quarantine..."
    if ! git clone --depth 1 https://github.com/renatodarrigo/claude-quarantine.git "$TEMP_DIR" 2>/dev/null; then
        echo "Error: Failed to clone repository. Make sure git is installed."
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    REPO_DIR="$TEMP_DIR"
    echo ""
fi
HOOKS_DIR="$CLAUDE_DIR/hooks"
MCP_DIR="$CLAUDE_DIR/mcp/claude-quarantine"

echo "claude-quarantine installer"
echo "==========================="
if [[ "$INSTALL_MODE" == "project" ]]; then
    echo "Mode: project-level (.claude/ in current directory)"
else
    echo "Mode: user-level (~/.claude/)"
fi
echo ""

# --- Install review skill ---
COMMANDS_DIR="$CLAUDE_DIR/commands"
echo "Installing /review-threats skill to $COMMANDS_DIR..."
mkdir -p "$COMMANDS_DIR"
cp "$REPO_DIR/review-threats.md" "$COMMANDS_DIR/"

# --- Install hooks ---
echo "Installing hooks to $HOOKS_DIR..."
mkdir -p "$HOOKS_DIR"
cp "$REPO_DIR/hooks/injection-guard.sh" "$HOOKS_DIR/"
cp "$REPO_DIR/hooks/injection-patterns.conf" "$HOOKS_DIR/"
chmod +x "$HOOKS_DIR/injection-guard.sh"

# Install config only if it doesn't exist (don't overwrite user config)
if [[ ! -f "$HOOKS_DIR/injection-guard.conf" ]]; then
    cp "$REPO_DIR/hooks/injection-guard.conf" "$HOOKS_DIR/"
    # For project installs, update LOG_FILE to use project-relative paths
    if [[ "$INSTALL_MODE" == "project" ]]; then
        sed -i.bak 's|LOG_FILE=~/.claude/hooks/|LOG_FILE=.claude/hooks/|' "$HOOKS_DIR/injection-guard.conf"
        rm -f "$HOOKS_DIR/injection-guard.conf.bak"
    fi
    echo "  Created default config at $HOOKS_DIR/injection-guard.conf"
else
    echo "  Config already exists at $HOOKS_DIR/injection-guard.conf (kept existing)"
fi

# --- Create .gitignore for project installs ---
if [[ "$INSTALL_MODE" == "project" ]]; then
    cat > "$CLAUDE_DIR/.gitignore" <<'GITIGNORE'
settings.local.json
hooks/injection-guard.log
hooks/confirmed-threats.json
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
        echo "  WARNING: settings.json exists but doesn't contain claude-quarantine config."
        echo "  You need to manually add the hook and MCP server configuration."
        echo "  See the README for the required settings.json entries."
    fi
else
    if [[ "$INSTALL_MODE" == "project" ]]; then
        cat > "$SETTINGS_FILE" <<'SETTINGS'
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "WebFetch|Bash|mcp__.*",
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
    "claude-quarantine": {
      "command": "node",
      "args": [".claude/mcp/claude-quarantine/dist/index.js"],
      "env": {
        "GUARD_CONFIG": ".claude/hooks/injection-guard.conf",
        "GUARD_PATTERNS": ".claude/hooks/injection-patterns.conf"
      }
    }
  }
}
SETTINGS
    else
        cat > "$SETTINGS_FILE" <<'SETTINGS'
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "WebFetch|Bash|mcp__.*",
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
    "claude-quarantine": {
      "command": "node",
      "args": ["~/.claude/mcp/claude-quarantine/dist/index.js"],
      "env": {
        "GUARD_CONFIG": "~/.claude/hooks/injection-guard.conf",
        "GUARD_PATTERNS": "~/.claude/hooks/injection-patterns.conf"
      }
    }
  }
}
SETTINGS
    fi
    echo "  Created settings.json with hook and MCP server config"
fi

echo ""
echo "Installation complete!"
echo ""
echo "Layer 1 (Pattern Scanner): Active on all WebFetch, Bash, and MCP tool results"
echo "Layer 3 (MCP Proxy):       Available as secure_fetch, secure_gh, secure_curl tools"
echo ""
echo "Configuration: $HOOKS_DIR/injection-guard.conf"
echo "Patterns:      $HOOKS_DIR/injection-patterns.conf"
echo "Logs:          $HOOKS_DIR/injection-guard.log"
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
