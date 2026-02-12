# Changelog

## 2.0.1

- `/guard-config` wizard: layer toggles now use multiSelect checkboxes instead of one-at-a-time editing
- `/guard-config` wizard: section selection no longer paginated — all sections shown at once

## 2.0.0

### New Features
- **Layer 0 — Pre-Tool-Use URL Blocklist**: New `PreToolUse` hook (`pretooluse-guard.sh`) checks URLs against a blocklist *before* tool execution. Pure bash, ~10ms latency. Supports local + remote cached blocklists.
- **Dry-Run / Audit Mode**: `GUARD_MODE=audit` — logs and warns but never blocks. No rate limit penalties in audit mode. All log entries tagged with `"mode": "audit"`.
- **Domain/URL Allowlisting**: URLs matching `allowlist.conf` patterns skip scanning entirely. Supports wildcard domains (`*.github.com`), port wildcards (`localhost:*`), and exact matches.
- **Per-Category Action Overrides**: `ACTION_<category>=block|warn|silent` in config. Override threat response per category (e.g., `ACTION_social_engineering=silent`).
- **Configurable Sanitization Strategies**: `SANITIZE_HIGH=redact|annotate|quarantine|passthrough`, `SANITIZE_MED=annotate|...`. New quarantine mode saves original content to file with metadata.
- **Content Fingerprint / Dedup Cache**: SHA-256 scan cache avoids re-scanning identical content. File-based (hook) + in-memory (MCP). Configurable TTL.
- **Split/Multi-Turn Payload Detection**: Session buffer tracks last N tool outputs and scans concatenated content to catch payloads split across multiple calls.
- **Log Rotation**: Automatic rotation by size (`LOG_MAX_SIZE`) or entry count (`LOG_MAX_ENTRIES`). Configurable rotation count. Uses flock for concurrency.
- **Pattern Severity Overrides**: `pattern-overrides.conf` lets you change built-in pattern severities without editing `injection-patterns.conf`. Survives updates.
- **Per-Layer Timeouts**: `LAYER1_TIMEOUT`, `LAYER2_TIMEOUT`, `LAYER4_TIMEOUT` — configurable timeouts for each layer.
- **Layer 2 Model Selection**: `LAYER2_MODEL=` config option to specify which model the LLM analysis layer uses.

### New Skills
- `/guard-stats` — Security dashboard showing threat counts, categories, false positive rates, time breakdowns, rate limit status
- `/test-pattern` — Interactive pattern tester: test regex against fixtures, check for false positives, offer to append to patterns file
- `/guard-config` — Configuration wizard: walk through all config options, manage pattern files, toggle layers, set up allowlists/blocklists

### Architecture
- Extracted helper libraries: `guard-lib-rotation.sh`, `guard-lib-allowlist.sh`, `guard-lib-cache.sh` — sourced by main hook
- MCP server updated to v2.0.0 with scan cache, allowlist support, quarantine strategy, and per-category action overrides

### Tests
- 8 new test suites: audit mode, log rotation, allowlist, Layer 0, scan cache, session buffer, category actions, sanitization strategies
- Target: ~120+ tests total (up from 70)

## 1.1.0

- Added `/update-guard` slash command for in-place updates
- Added `VERSION` file and `.guard-version` marker for version tracking
- Added `CHANGELOG.md`

## 1.0.0

- Initial release
- Layer 1: Pattern scanner (28 patterns, 8 threat categories)
- Layer 2: LLM analysis via `claude -p`
- Layer 3: MCP sanitization proxy (`secure_fetch`, `secure_gh`, `secure_curl`)
- `/review-threats` slash command for threat triage
- User-level and project-level installation
- 68 automated tests
