# Harness Extensions Design

## Goal

Extend the public dotfiles repository to preserve useful Pi and OpenCode harness configuration while excluding authentication state and sanitizing API endpoints and secrets.

## Sources and Destinations

Pi:

- `~/.pi/agent/settings.json` → `configs/pi/settings.json`, copied verbatim per explicit user approval.
- `~/.pi/agent/mcp.json` → `configs/pi/mcp.json`, copied only after safety validation.
- `~/.pi/agent/models.json` → `configs/pi/models.json`, sanitized before writing.
- Exclude `auth.json`, `mcp-cache.json`, `run-history.jsonl`, sessions, tasks, state, caches, model stores, and installed package source/dependencies. `pi-mcp-adapter` remains represented by the package entry in `settings.json` and is reinstalled by Pi's package manager.

OpenCode:

- `~/.config/opencode/opencode.json` → `configs/opencode/opencode.json`, sanitized before writing.
- `~/.config/opencode/opencode-openai-compatible.json` → `configs/opencode/opencode-openai-compatible.json`, sanitized before writing.
- `~/.config/opencode/dcp.jsonc` → `configs/opencode/dcp.jsonc`.
- Recursively sync safe files from `plugins/`, `skills/`, `agents/`, `commands/`, and `tools/`, with filename/content safety screening.
- Exclude `auth.json`, `.ocx/`, `node_modules/`, caches, package locks, generated profiles, and runtime state.

## Sync Model

The manifest becomes an explicit set of source entries with modes:

- `file`: copy a single file after validation.
- `sanitized_json` / `sanitized_jsonc`: parse JSON or JSONC, recursively replace approved endpoint and secret values, then write deterministic sanitized JSON. Source files remain unchanged.
- `directory`: recursively enumerate only the named directory root, skip excluded directories/files, validate each file, and copy into the matching repository subtree. Directory roots are explicit; the script never discovers sibling roots.

All source and destination paths retain existing traversal, symlink, hardlink, regular-file, bounded-read, atomic-write, and public-safety protections.

## Sanitization

Sanitized files preserve configuration shape while replacing sensitive values with environment placeholders:

- API base URLs/hostnames → `${PI_API_BASE_URL}` or `${OPENCODE_API_BASE_URL}`.
- Provider/API keys → `${PI_PROVIDER_API_KEY}` or `${OPENCODE_API_KEY}`.
- Generic secret/token/password/header credential values → field-specific environment placeholders where safe.

Sanitization is key/path based and fail-closed: unknown sensitive fields or credential-like values are rejected rather than copied. Original source files are never modified. Placeholder names contain no real values. Sanitized output still passes the repository scanner.

The tool never reads or writes `auth.json`. Installed package directories are never copied.

## CLI

Existing commands remain:

```text
python scripts/sync.py export
python scripts/sync.py install
python scripts/sync.py check
```

`export` applies manifest modes and sanitization. `install` writes sanitized repository output and safe raw files. `check` validates manifest roots, presence, exclusions, and sanitized output without modifying files. `--dry-run` remains non-mutating; `install --force` remains required for overwriting existing files.

## Testing

Extend `tests/test_sync.py` with temporary-root tests for:

- New Pi and OpenCode manifest entries.
- Explicit recursive directory roots and exclusion of sibling/unlisted directories.
- Raw `mcp.json` handling.
- JSON/JSONC sanitization of endpoint hostnames, API keys, tokens, headers, and nested provider fields.
- Placeholder output and source immutability.
- Rejection/exclusion of `auth.json`, caches, package locks, node_modules, and runtime state.
- Pi settings copy behavior.
- `check` and dry-run non-modification.
- Existing security, path, link, bounded-read, atomic-write, and overwrite tests.

Verification remains unittest, Python compilation, `git diff --check`, and a public-safety scan that distinguishes detector patterns from actual credential-shaped values.

## Documentation

Update `README.md` with the new mappings, sanitization behavior, required environment variables, exclusions, and the warning that sanitized configs require local environment setup. Update `AGENTS.md` to require manual review of sanitization rules and forbid auth/runtime/package directories.
