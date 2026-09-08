# Pi and OpenCode Dotfiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a public-safe Pi/OpenCode dotfiles repository with a dependency-free Python allowlist sync tool for Windows and macOS.

**Architecture:** A static manifest in `scripts/sync.py` maps sanitized repository files to platform-specific user paths. The CLI validates paths and content before copying, supports `export`, `install`, and `check`, and never scans or deletes unlisted files.

**Tech Stack:** Python 3.10+ standard library, `argparse`, `pathlib`, `shutil`, `unittest`, Git.

---

## File Map

- Create: `scripts/sync.py` — manifest, platform path resolution, security validation, copy operations, CLI.
- Create: `tests/test_sync.py` — isolated unit tests using temporary directories and injected platform roots.
- Create: `configs/pi/AGENTS.md` — sanitized Pi harness maintenance guidance.
- Create: `configs/opencode/AGENTS.md` — sanitized OpenCode harness maintenance guidance.
- Create: `README.md` — concise usage and safety documentation.
- Create: `AGENTS.md` — repository maintenance rules for harness agents.
- Create: `.gitignore` — prevent local secrets, caches, generated files, and Python artifacts.
- Preserve: `docs/superpowers/specs/2026-04-06-pi-opencode-dotfiles-design.md` — approved design.

### Task 1: Add safety tests

**Files:**

- Create: `tests/test_sync.py`

- [ ] **Step 1: Write tests for path resolution and manifest validation**

```python
import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "sync.py"
spec = importlib.util.spec_from_file_location("sync", MODULE_PATH)
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class SyncTests(unittest.TestCase):
    def test_resolve_destination_supports_windows_and_macos(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            appdata = Path(temp) / "appdata"
            self.assertEqual(
                sync.resolve_destination("windows", "home", "x", home=home, appdata=appdata),
                home / "x",
            )
            self.assertEqual(
                sync.resolve_destination("windows", "appdata", "x", home=home, appdata=appdata),
                appdata / "x",
            )
            self.assertEqual(
                sync.resolve_destination("darwin", "home", "x", home=home, appdata=appdata),
                home / "x",
            )

    def test_unsupported_platform_fails(self):
        with self.assertRaises(sync.SyncError):
            sync.resolve_destination("linux", "home", "x", home=Path("/tmp"), appdata=None)

    def test_manifest_rejects_traversal(self):
        with self.assertRaises(sync.SyncError):
            sync.validate_relative_path(Path("../secret"))

    def test_manifest_only_contains_safe_paths(self):
        for item in sync.MANIFEST:
            self.assertFalse(sync.is_sensitive_path(Path(item.repo_path)))
            self.assertFalse(sync.is_sensitive_path(Path(item.relative_path)))

    def test_content_scanner_rejects_credential_markers(self):
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(b'api_key = "abc"')

    def test_unlisted_file_is_not_exported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            repo = root / "repo"
            source.mkdir()
            repo.mkdir()
            (source / "unlisted.txt").write_text("safe", encoding="utf-8")
            sync.export_files([], repo)
            self.assertFalse((repo / "unlisted.txt").exists())

    def test_dry_run_does_not_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            destination = root / "destination.txt"
            source.write_text("safe", encoding="utf-8")
            sync.copy_file(source, destination, dry_run=True, force=False)
            self.assertFalse(destination.exists())

    def test_install_does_not_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            destination = root / "destination.txt"
            source.write_text("new", encoding="utf-8")
            destination.write_text("old", encoding="utf-8")
            with self.assertRaises(sync.SyncError):
                sync.copy_file(source, destination, dry_run=False, force=False)
            self.assertEqual(destination.read_text(encoding="utf-8"), "old")

    def test_force_overwrites(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            destination = root / "destination.txt"
            source.write_text("new", encoding="utf-8")
            destination.write_text("old", encoding="utf-8")
            sync.copy_file(source, destination, dry_run=False, force=True)
            self.assertEqual(destination.read_text(encoding="utf-8"), "new")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests and verify the expected initial failure**

Run: `python -m unittest discover -s tests -v`

Expected: FAIL because `scripts/sync.py` does not exist yet.

- [ ] **Step 3: Commit the tests**

```bash
git add tests/test_sync.py
git commit -m "test: define safe dotfiles sync behavior"
```

### Task 2: Implement the minimal safe sync tool

**Files:**

- Create: `scripts/sync.py`

- [ ] **Step 1: Implement the manifest and platform resolver**

```python
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


class SyncError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mapping:
    app: str
    repo_path: str
    platform_root: str
    relative_path: str
    required: bool = False


MANIFEST = (
    Mapping("pi", "configs/pi/AGENTS.md", "home", ".pi/AGENTS.md"),
    Mapping("opencode", "configs/opencode/AGENTS.md", "home", ".config/opencode/AGENTS.md"),
)

SENSITIVE_PARTS = re.compile(
    r"(^|[-_.])(auth|token|secret|credential|password|cookie|history|session|cache|log)([-_.]|$)",
    re.IGNORECASE,
)
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3"}
SECRET_MARKERS = re.compile(
    r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|password)\s*[:=]"
)


def validate_relative_path(path: Path) -> None:
    if path.is_absolute() or ".." in path.parts:
        raise SyncError(f"path escapes root: {path}")


def is_sensitive_path(path: Path) -> bool:
    return any(SENSITIVE_PARTS.search(part) for part in path.parts) or path.suffix.lower() in SENSITIVE_SUFFIXES


def ensure_safe_content(content: bytes) -> None:
    if SECRET_MARKERS.search(content.decode("utf-8", errors="replace")):
        raise SyncError("refusing content that resembles a credential")


def resolve_destination(platform: str, root: str, relative_path: str, *, home: Path, appdata: Path | None) -> Path:
    if platform == "win32":
        base = home if root == "home" else appdata if root == "appdata" else None
    elif platform == "darwin":
        base = home if root == "home" else None
    else:
        base = None
    if base is None:
        raise SyncError(f"unsupported platform or root: {platform}/{root}")
    relative = Path(relative_path)
    validate_relative_path(relative)
    return base / relative


def copy_file(source: Path, destination: Path, *, dry_run: bool, force: bool) -> None:
    if is_sensitive_path(source) or is_sensitive_path(destination):
        raise SyncError(f"refusing sensitive path: {source}")
    if not source.is_file():
        raise SyncError(f"source file not found: {source}")
    ensure_safe_content(source.read_bytes())
    if destination.exists() and not force:
        raise SyncError(f"destination exists; use --force: {destination}")
    print(f"{'would copy' if dry_run else 'copy'} {source} -> {destination}")
    if not dry_run:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def export_files(manifest, repo_root: Path, *, platform: str = sys.platform, home: Path | None = None, appdata: Path | None = None, dry_run: bool = False) -> int:
    home = home or Path.home()
    appdata = appdata or Path(os.environ["APPDATA"]) if platform == "win32" and "APPDATA" in os.environ else appdata
    count = 0
    for item in manifest:
        source = resolve_destination(platform, item.platform_root, item.relative_path, home=home, appdata=appdata)
        destination = repo_root / item.repo_path
        validate_relative_path(Path(item.repo_path))
        if not source.exists():
            if item.required:
                raise SyncError(f"required source file not found: {source}")
            print(f"skip missing {source}")
            continue
        copy_file(source, destination, dry_run=dry_run, force=True)
        count += 1
    return count


def install_files(manifest, repo_root: Path, *, platform: str = sys.platform, home: Path | None = None, appdata: Path | None = None, dry_run: bool = False, force: bool = False) -> int:
    home = home or Path.home()
    appdata = appdata or Path(os.environ["APPDATA"]) if platform == "win32" and "APPDATA" in os.environ else appdata
    count = 0
    for item in manifest:
        source = repo_root / item.repo_path
        validate_relative_path(Path(item.repo_path))
        destination = resolve_destination(platform, item.platform_root, item.relative_path, home=home, appdata=appdata)
        if not source.exists():
            if item.required:
                raise SyncError(f"required repository file not found: {source}")
            print(f"skip missing {source}")
            continue
        copy_file(source, destination, dry_run=dry_run, force=force)
        count += 1
    return count


def check_files(manifest, repo_root: Path, *, platform: str = sys.platform, home: Path | None = None, appdata: Path | None = None) -> int:
    home = home or Path.home()
    appdata = appdata or Path(os.environ["APPDATA"]) if platform == "win32" and "APPDATA" in os.environ else appdata
    failures = 0
    for item in manifest:
        source = resolve_destination(platform, item.platform_root, item.relative_path, home=home, appdata=appdata)
        repo_file = repo_root / item.repo_path
        for label, path in (("source", source), ("repo", repo_file)):
            try:
                validate_relative_path(path.relative_to(home if label == "source" else repo_root))
            except ValueError:
                raise SyncError(f"path escapes root: {path}")
            if path.exists():
                print(f"ok {label} {path}")
            elif item.required:
                print(f"missing required {label} {path}")
                failures += 1
            else:
                print(f"missing optional {label} {path}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Safely sync allowlisted Pi and OpenCode settings")
    parser.add_argument("command", choices=("export", "install", "check"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        if args.command == "export":
            export_files(MANIFEST, repo_root, dry_run=args.dry_run)
        elif args.command == "install":
            install_files(MANIFEST, repo_root, dry_run=args.dry_run, force=args.force)
        else:
            return check_files(MANIFEST, repo_root)
    except (KeyError, OSError, SyncError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Run the focused tests**

Run: `python -m unittest discover -s tests -v`

Expected: PASS for all tests.

- [ ] **Step 3: Run Python compilation**

Run: `python -m py_compile scripts/sync.py tests/test_sync.py`

Expected: exit code 0 and no output.

- [ ] **Step 4: Commit the implementation**

```bash
git add scripts/sync.py
git commit -m "feat: add safe cross-platform dotfiles sync"
```

### Task 3: Add sanitized harness instructions and repository policy

**Files:**

- Create: `configs/pi/AGENTS.md`
- Create: `configs/opencode/AGENTS.md`
- Create: `AGENTS.md`
- Create: `.gitignore`

- [ ] **Step 1: Add the two sanitized config instruction files**

`configs/pi/AGENTS.md`:

```markdown
# Pi Settings

Keep Pi configuration portable and public-safe. Store behavior, formatting, and workflow preferences only. Never add credentials, auth state, history, logs, caches, or machine-specific paths.
```

`configs/opencode/AGENTS.md`:

```markdown
# OpenCode Settings

Keep OpenCode configuration portable and public-safe. Store behavior and workflow preferences only. Never add credentials, auth state, history, logs, caches, or machine-specific paths.
```

- [ ] **Step 2: Add root agent instructions**

```markdown
# AGENTS.md

## Rules

- Keep the sync manifest explicit and allowlist-only.
- Never commit API keys, tokens, passwords, cookies, private keys, auth state, history, logs, caches, databases, or machine-specific secrets.
- Review every new config file manually before adding it to `scripts/sync.py`.
- Prefer Python standard library and the smallest safe diff.
- Do not broaden directory copies or weaken secret screening.

## Checks

```text
python -m unittest discover -s tests -v
python -m py_compile scripts/sync.py tests/test_sync.py
git diff --check
```

```

- [ ] **Step 3: Add public-repo exclusions**

```gitignore
# Python
__pycache__/
*.py[cod]
.venv/
venv/

# Local harness state
.env
.env.*
*.log
*.db
*.sqlite
*.sqlite3

# Secrets and private material
*.pem
*.key
*.p12
*.pfx
**/auth*/
**/*token*/
**/*secret*/
**/*credential*/
**/*password*/
**/*cookie*/
**/*history*/
**/*session*/
**/*cache*/
```

- [ ] **Step 4: Commit policy files**

```bash
git add configs AGENTS.md .gitignore
git commit -m "docs: add public-safe harness maintenance rules"
```

### Task 4: Write README and verify end to end

**Files:**

- Create: `README.md`

- [ ] **Step 1: Write concise README**

```markdown
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

`export` copies only files listed in `scripts/sync.py` from user config locations into `configs/`. `install` copies those files back. `check` reports missing files. Missing optional files are skipped.

## Safety

This is a public repository. The manifest is allowlist-only. The script rejects sensitive paths and common credential markers, never copies unknown files, never deletes repository files, and requires `--force` before overwriting during install.

Review every exported diff before committing. Do not add credentials, auth state, tokens, cookies, private keys, history, logs, caches, databases, or machine-specific paths.

```

- [ ] **Step 2: Run all verification commands**

Run:

```bash
python -m unittest discover -s tests -v
python -m py_compile scripts/sync.py tests/test_sync.py
git diff --check
git status --short
```

Expected: all tests pass; compilation succeeds; `git diff --check` prints nothing; status lists only intended files before commit.

- [ ] **Step 3: Run a public-safety scan**

Run:

```bash
python - <<'PY'
from pathlib import Path
text = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in Path(".").rglob("*") if p.is_file() and ".git" not in p.parts)
for marker in ("sk-api-", "ghp_", "-----BEGIN PRIVATE KEY-----", "AKIA"):
    assert marker not in text, marker
print("public safety scan: passed")
PY
```

Expected: `public safety scan: passed`.

- [ ] **Step 4: Commit README and final changes**

```bash
git add README.md
git commit -m "docs: document dotfiles sync usage and safety"
```

- [ ] **Step 5: Inspect final repository state**

Run: `git status --short --branch && git log --oneline --decorate -5`

Expected: clean working tree with the implementation and documentation commits visible.
