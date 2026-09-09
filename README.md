# Pi/OpenCode Dotfiles

Public-safe settings for the Pi and OpenCode harnesses. Windows and macOS first.

## Usage

Requires Python 3.10+.

```bash
python scripts/sync.py check
python scripts/sync.py export --dry-run
python scripts/sync.py export
python scripts/sync.py install --dry-run
python scripts/sync.py install --force
```

`export` copies only files and explicit directories listed in `scripts/sync.py` from user configuration locations into `configs/`. Pi settings and MCP files are copied after safety checks; Pi models and OpenCode JSON configs are sanitized to environment placeholders before export. OpenCode `plugins/`, `skills/`, `agents/`, `commands/`, and `tools/` roots are recursively synced with exclusions. `install` copies repository files back. `check` reports missing files. Missing optional files are skipped. `--dry-run` previews actions without changing files. `install` requires `--force` to overwrite existing files.

Sanitized configs use `${PI_API_BASE_URL}`, `${PI_PROVIDER_API_KEY}`, `${PI_LOCAL_PATH}`, `${OPENCODE_API_BASE_URL}`, `${OPENCODE_API_KEY}`, `${OPENCODE_LOCAL_PATH}`, `${OPENCODE_LOCAL_PLUGIN_PATH}`, and `${OPENCODE_HEADROOM_COMMAND}`. Set these locally before using installed configs. Pi `settings.json` is intentionally copied verbatim by explicit user approval; review it manually before every commit.

The manifest never syncs `auth.json`, `mcp-cache.json`, history, sessions, caches, runtime state, package locks, `node_modules`, or installed `pi-mcp-adapter` source. Pi's `settings.json` retains the package declaration so Pi can reinstall it.

## Safety

This is a public repository. The manifest is allowlist-only: unknown files are never copied. The script rejects sensitive paths and common credential markers, never deletes repository files, and never disables safety checks with `--force`.

Review every exported diff before committing. Never add credentials, auth state, API keys, tokens, cookies, private keys, history, logs, caches, databases, package dependencies, or machine-specific paths.

The tool rejects symlinks and hardlinks, uses bounded reads, and publishes copies atomically. Lowercase short Base64-like words remain unclassified to avoid treating ordinary words as encoded data. Credential screening is defense in depth; review exported diffs manually. Path-based checks cannot eliminate every concurrent path-swap race; Windows reparse-point behavior also depends on filesystem and OS details.
