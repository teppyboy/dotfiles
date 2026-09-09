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

`export` copies only files listed in `scripts/sync.py` from user configuration locations into `configs/`. `install` copies those files back. `check` reports missing files. Missing optional files are skipped. `--dry-run` previews actions without changing files. `install` requires `--force` to overwrite existing files.

## Safety

This is a public repository. The manifest is allowlist-only: unknown files are never copied. The script rejects sensitive paths and common credential markers, never deletes repository files, and never disables safety checks with `--force`.

Review every exported diff before committing. Never add credentials, auth state, API keys, tokens, cookies, private keys, history, logs, caches, databases, or machine-specific paths.

The tool rejects symlinks and hardlinks, uses bounded reads, and publishes copies atomically. Lowercase short Base64-like words remain unclassified to avoid treating ordinary words as encoded data. Credential screening is defense in depth; review exported diffs manually. Path-based checks cannot eliminate every concurrent path-swap race; Windows reparse-point behavior also depends on filesystem and OS details.
