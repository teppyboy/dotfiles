"""Safely sync the allowlisted Pi and OpenCode settings."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


class SyncError(RuntimeError):
    """An unsafe or otherwise invalid sync operation."""


@dataclass(frozen=True)
class Mapping:
    """A repository file and its user configuration destination."""

    app: str
    repo_path: str
    platform_root: str
    relative_path: str
    required: bool = False


# Keep this list explicit. Never replace it with directory discovery.
MANIFEST = (
    Mapping("pi", "configs/pi/AGENTS.md", "home", ".pi/AGENTS.md"),
    Mapping(
        "opencode",
        "configs/opencode/AGENTS.md",
        "home",
        ".config/opencode/AGENTS.md",
    ),
)

SENSITIVE_NAMES = (
    "auth",
    "token",
    "secret",
    "credential",
    "password",
    "cookie",
    "history",
    "session",
    "cache",
    "log",
)
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3"}
CREDENTIAL_MARKERS = (
    re.compile(
        r"(?i)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
        r"client[_-]?secret|private[_-]?key|password|secret)\s*[:=]"
    ),
    re.compile(r"-----BEGIN [^-\n]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}"),
)


def validate_relative_path(path: Path) -> None:
    """Reject absolute paths and paths that contain parent traversal."""
    if path.is_absolute() or path.anchor or ".." in path.parts:
        raise SyncError(f"path escapes root: {path}")


def is_sensitive_path(path: Path) -> bool:
    """Return whether a path looks like private or generated application data."""
    return any(
        any(name in part.casefold() for name in SENSITIVE_NAMES) for part in path.parts
    ) or path.suffix.casefold() in SENSITIVE_SUFFIXES


def ensure_safe_content(content: bytes) -> None:
    """Reject common credential formats without exposing file contents."""
    text = content.decode("utf-8", errors="replace")
    if any(marker.search(text) for marker in CREDENTIAL_MARKERS):
        raise SyncError("refusing content that resembles a credential")


def _safe_join(root: Path, relative_path: str | Path) -> Path:
    relative = Path(relative_path)
    validate_relative_path(relative)
    root = root.expanduser().absolute()
    candidate = (root / relative).absolute()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise SyncError(f"path escapes root: {relative}") from exc
    return candidate


def resolve_destination(
    platform: str,
    root: str,
    relative_path: str,
    *,
    home: Path,
    appdata: Path | None,
) -> Path:
    """Resolve an allowlisted destination using injected platform roots."""
    if platform in {"win32", "windows"} and root == "home":
        base = home
    elif platform in {"win32", "windows"} and root == "appdata":
        base = appdata
    elif platform in {"darwin", "macos"} and root == "home":
        base = home
    else:
        base = None
    if base is None:
        raise SyncError(f"unsupported platform or root: {platform}/{root}")
    return _safe_join(base, relative_path)


def _defaults(
    platform: str, home: Path | None, appdata: Path | None
) -> tuple[Path, Path | None]:
    resolved_home = home if home is not None else Path.home()
    resolved_appdata = appdata
    if resolved_appdata is None and platform in {"win32", "windows"}:
        value = os.environ.get("APPDATA")
        if value:
            resolved_appdata = Path(value)
    return resolved_home, resolved_appdata


def _validate_manifest(manifest: Iterable[Mapping]) -> tuple[Mapping, ...]:
    entries = tuple(manifest)
    repo_paths: set[str] = set()
    for item in entries:
        validate_relative_path(Path(item.repo_path))
        validate_relative_path(Path(item.relative_path))
        if is_sensitive_path(Path(item.repo_path)) or is_sensitive_path(
            Path(item.relative_path)
        ):
            raise SyncError(f"manifest contains a sensitive path: {item.repo_path}")
        if item.repo_path in repo_paths:
            raise SyncError(f"manifest contains duplicate path: {item.repo_path}")
        repo_paths.add(item.repo_path)
    return entries


def copy_file(
    source: Path,
    destination: Path,
    *,
    dry_run: bool,
    force: bool,
) -> None:
    """Validate and copy one file, preserving existing destinations by default."""
    if is_sensitive_path(source) or is_sensitive_path(destination):
        raise SyncError(f"refusing sensitive path: {source}")
    if not source.is_file():
        raise SyncError(f"source file not found: {source}")
    ensure_safe_content(source.read_bytes())
    if destination.exists() and not force:
        raise SyncError(f"destination exists; use --force: {destination}")
    action = "would copy" if dry_run else "copy"
    print(f"{action} {source} -> {destination}")
    if not dry_run:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def export_files(
    manifest: Iterable[Mapping],
    repo_root: Path,
    *,
    platform: str = sys.platform,
    home: Path | None = None,
    appdata: Path | None = None,
    dry_run: bool = False,
) -> int:
    """Export existing allowlisted user files into the repository."""
    entries = _validate_manifest(manifest)
    home, appdata = _defaults(platform, home, appdata)
    count = 0
    for item in entries:
        source = resolve_destination(
            platform, item.platform_root, item.relative_path, home=home, appdata=appdata
        )
        destination = _safe_join(repo_root, item.repo_path)
        if not source.exists():
            if item.required:
                raise SyncError(f"required source file not found: {source}")
            print(f"skip missing {source}")
            continue
        copy_file(source, destination, dry_run=dry_run, force=True)
        count += 1
    return count


def install_files(
    manifest: Iterable[Mapping],
    repo_root: Path,
    *,
    platform: str = sys.platform,
    home: Path | None = None,
    appdata: Path | None = None,
    dry_run: bool = False,
    force: bool = False,
) -> int:
    """Install existing allowlisted repository files into user destinations."""
    entries = _validate_manifest(manifest)
    home, appdata = _defaults(platform, home, appdata)
    count = 0
    for item in entries:
        source = _safe_join(repo_root, item.repo_path)
        destination = resolve_destination(
            platform, item.platform_root, item.relative_path, home=home, appdata=appdata
        )
        if not source.exists():
            if item.required:
                raise SyncError(f"required repository file not found: {source}")
            print(f"skip missing {source}")
            continue
        copy_file(source, destination, dry_run=dry_run, force=force)
        count += 1
    return count


def check_files(
    manifest: Iterable[Mapping],
    repo_root: Path,
    *,
    platform: str = sys.platform,
    home: Path | None = None,
    appdata: Path | None = None,
) -> int:
    """Report allowlisted source/repository files and return required failures."""
    entries = _validate_manifest(manifest)
    home, appdata = _defaults(platform, home, appdata)
    failures = 0
    for item in entries:
        source = resolve_destination(
            platform, item.platform_root, item.relative_path, home=home, appdata=appdata
        )
        repo_file = _safe_join(repo_root, item.repo_path)
        for label, path in (("source", source), ("repo", repo_file)):
            if path.exists():
                try:
                    if not path.is_file():
                        raise SyncError(f"expected file but found non-file: {path}")
                    if is_sensitive_path(path):
                        raise SyncError(f"refusing sensitive path: {path}")
                    ensure_safe_content(path.read_bytes())
                except (OSError, SyncError) as exc:
                    print(f"unsafe {label} {path}: {exc}")
                    failures += 1
                else:
                    print(f"ok {label} {path}")
            elif item.required:
                print(f"missing required {label} {path}")
                failures += 1
            else:
                print(f"missing optional {label} {path}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Safely sync allowlisted Pi and OpenCode settings"
    )
    parser.add_argument("command", choices=("export", "install", "check"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        if args.command == "export":
            export_files(MANIFEST, repo_root, dry_run=args.dry_run)
        elif args.command == "install":
            install_files(
                MANIFEST, repo_root, dry_run=args.dry_run, force=args.force
            )
        else:
            return check_files(MANIFEST, repo_root)
    except (KeyError, OSError, SyncError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
