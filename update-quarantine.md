You are updating the claude-quarantine installation to the latest version from GitHub.

## File locations

Detect the install location by checking for the hook script:

- **Project-level**: Check if `.claude/hooks/injection-guard.sh` exists in the current working directory. If so, use `.claude/` as the install root.
- **User-level**: Otherwise, use `~/.claude/` as the install root.

The version marker file is `{CLAUDE_DIR}/.quarantine-version` where `{CLAUDE_DIR}` is the detected install root (`.claude/` or `~/.claude/`).

## Procedure

1. **Detect install location** — check if `.claude/hooks/injection-guard.sh` exists in the current working directory. If yes, this is a project-level install (`CLAUDE_DIR=.claude`). Otherwise, check `~/.claude/hooks/injection-guard.sh` for a user-level install (`CLAUDE_DIR=~/.claude`). If neither exists, tell the user claude-quarantine doesn't appear to be installed and stop.

2. **Read installed version** — read the file `{CLAUDE_DIR}/.quarantine-version`. If it doesn't exist, the installed version is "unknown (pre-1.1.0)".

3. **Fetch latest version** — run:
   ```
   curl -fsSL https://raw.githubusercontent.com/renatodarrigo/claude-quarantine/main/VERSION
   ```
   This returns the latest version string. Trim any whitespace.

4. **Compare versions** — if the installed version equals the latest version, tell the user: "claude-quarantine is already up to date (v{version})." and stop.

5. **Show version delta** — display:
   ```
   Installed: v{installed_version}
   Latest:    v{latest_version}
   ```

6. **Fetch changelog (optional)** — attempt to fetch:
   ```
   curl -fsSL https://raw.githubusercontent.com/renatodarrigo/claude-quarantine/main/CHANGELOG.md
   ```
   If successful, display the section for the latest version. If it fails, skip silently.

7. **Confirm with user** — use AskUserQuestion to ask: "Update claude-quarantine to v{latest_version}?" with options "Update now" and "Skip". If the user chooses "Skip", stop.

8. **Run the installer** — execute the appropriate command:
   - **User-level install**:
     ```
     curl -fsSL https://raw.githubusercontent.com/renatodarrigo/claude-quarantine/main/install.sh | bash
     ```
   - **Project-level install** (determine the project root as the parent of `.claude/`):
     ```
     curl -fsSL https://raw.githubusercontent.com/renatodarrigo/claude-quarantine/main/install.sh | bash -s -- --project={PROJECT_DIR}
     ```
   Where `{PROJECT_DIR}` is the absolute path of the directory containing `.claude/`.

9. **Verify update** — re-read `{CLAUDE_DIR}/.quarantine-version` and confirm it now matches the latest version.

10. **Report results** — tell the user:
    - Updated from v{old} to v{new}
    - List what was updated: hooks, patterns, MCP server, skills
    - List what was preserved: `injection-guard.conf` (user config), `injection-guard.log` (detection log), `confirmed-threats.json` (confirmed threats), `settings.json` (if it already existed)

## Important rules

- Do NOT implement file-copy logic yourself. Always delegate to `install.sh` which handles config preservation, path differences, and all installation details.
- Do NOT modify `settings.json` directly. The installer handles this.
- If the curl commands fail (no internet, GitHub down), report the error clearly and stop.
- The installer preserves `injection-guard.conf` if it already exists — this is by design. Do not warn about config being overwritten.
- Always show the user what version they're on before and after the update.
