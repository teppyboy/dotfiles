# Pi and OpenCode Dotfiles Design

## Goal

Create a public Git repository for safe, portable Pi and OpenCode harness settings, with a dependency-free Python sync tool supporting Windows and macOS first.

## Scope

The repository contains only explicitly allowlisted, non-sensitive configuration and instruction files. It does not mirror entire application directories.

Initial commands:

```text
python scripts/sync.py export
python scripts/sync.py install
python scripts/sync.py check
```

`export` copies safe live user files into the repository. `install` copies repository files to the current user's platform-specific locations. `check` reports missing expected files and unsafe mappings without modifying files.

## Repository Layout

```text
configs/
  pi/
  opencode/
scripts/
  sync.py
tests/
  test_sync.py
README.md
AGENTS.md
.gitignore
```

The repository may add sanitized examples or instruction files under `configs/`, but each file must be represented by an explicit mapping in `scripts/sync.py`.

## Sync Manifest

The sync tool defines a small static allowlist of relative mappings. Each mapping has:

- application identifier (`pi` or `opencode`)
- repository-relative path
- platform-specific user destination path
- optional status, if a file is not present on every installation

The tool rejects mappings that escape the repository or destination roots. It never discovers or copies unlisted files.

Windows paths use environment-resolved user directories such as `%APPDATA%` and `%USERPROFILE%`. macOS paths use `Path.home()` and application-support directories such as `~/Library/Application Support` where applicable. Unsupported operating systems fail with a clear error.

## Security Boundary

Public-repository safety is a hard requirement:

- Never sync credentials, auth state, API keys, tokens, cookies, private keys, databases, history, logs, caches, or session data.
- Reject secret-like path components and filenames, including names containing `auth`, `token`, `secret`, `credential`, `password`, `cookie`, `history`, `session`, `cache`, `log`, or private-key extensions unless explicitly safe and reviewed.
- Scan file contents for common credential markers before `export` writes anything.
- Use `shutil.copy2` only after source and destination validation.
- Do not print file contents or sensitive values; display paths and action summaries only.
- `export` never deletes repository files.
- `install` does not overwrite existing files unless the user passes an explicit overwrite option; dry-run is available for both directions.

The deny rules are defense in depth, not a replacement for manual review. `.gitignore` also excludes local secrets, caches, virtual environments, and generated files.

## CLI Behavior

- `export`: copy existing allowlisted source files into `configs/`; skip absent optional files; fail on unsafe content or invalid paths.
- `install`: copy allowlisted repository files to user destinations; skip absent optional files; require `--force` to overwrite; support `--dry-run`.
- `check`: validate manifest paths and report source/repository presence without modifying files.
- `--dry-run`: print planned actions only.
- `--force`: permit overwriting during `install`; never weakens secret screening.
- Exit non-zero on invalid platform, invalid manifest, unsafe files, or required-file failures.

No third-party dependencies. Use Python 3.10+ standard library APIs.

## Testing

Use `unittest` and temporary directories. Tests cover:

- Windows and macOS path resolution through injected roots or platform helpers.
- Allowlist-only behavior.
- Missing optional files.
- Secret-like paths and credential markers.
- Dry-run non-modification.
- Install overwrite protection and `--force` behavior.
- Manifest/path traversal validation.

Verification includes Python compilation, the test suite, `git diff --check`, and a repository scan for sensitive names and credential markers.

## Documentation

`README.md` explains setup, commands, supported platforms, and the public-repository safety model concisely.

`AGENTS.md` tells future harness agents to preserve the allowlist, never add secret-bearing files, run tests and safety checks, and keep changes minimal.
