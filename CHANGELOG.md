# Changelog

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
