"""Safely sync the allowlisted Pi and OpenCode settings."""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import contextlib
import os
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote


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
    "private",
    "keyring",
    "wallet",
    "private_key",
    "private-key",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
)
SENSITIVE_SUFFIXES = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".asc",
    ".gpg",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".ppk",
    ".p8",
    ".jks",
    ".jceks",
    ".keystore",
}
SENSITIVE_NAME_PATTERNS = (
    re.compile(r"(?i)(?:^|[-_.])api[_-]?key(?:$|[-_.])"),
    re.compile(r"(?i)(?:^|[-_.])apikey(?:$|[-_.])"),
    re.compile(r"(?i)(?:^|[-_.])private(?:[-_]key)?(?:$|[-_.])"),
    re.compile(r"(?i)(?:^|[-_.])id_(?:rsa|dsa|ecdsa|ed25519)(?:$|[-_.])"),
    re.compile(r"(?i)^\.env(?:$|[._-])"),
)
MAX_CONTENT_BYTES = 8 * 1024 * 1024
MAX_BASE64_CANDIDATES = 256
MAX_BASE64_BYTES = 1024 * 1024
MAX_BASE64_CHARS = (MAX_BASE64_BYTES * 4 // 3) + 4
CREDENTIAL_MARKERS = (
    re.compile(
        r"(?im)(?<![A-Za-z0-9])(?:[A-Za-z][A-Za-z0-9_-]*?(?:api[_-]?key|"
        r"access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|"
        r"auth(?:entication|orization)?|token|credential(?:s)?|password|secret|"
        r"cookie|history|session)[A-Za-z0-9_-]*|api[_-]?key|access[_-]?token|"
        r"refresh[_-]?token|client[_-]?secret|private[_-]?key|auth|token|"
        r"credentials?|password|secret|cookie|history|session)\s*['\"]?\s*[:=]"
    ),
    re.compile(r"-----BEGIN [^-\n]*PRIVATE KEY-----"),
    re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    re.compile(r"(?i)['\"](?:d|p|q|dp|dq|qi)['\"]\s*:\s*['\"][^'\"]+['\"]"),
    re.compile(
        r"(?is)\{[^{}]{0,4096}\"kty\"\s*:\s*\"(?:oct|OKP)\""
        r"[^{}]{0,4096}\"k\"\s*:\s*\"[^\"]+\"[^{}]{0,4096}\}"
    ),
    re.compile(
        r"(?is)\{[^{}]{0,4096}\"k\"\s*:\s*\"[^\"]+\""
        r"[^{}]{0,4096}\"kty\"\s*:\s*\"(?:oct|OKP)\"[^{}]{0,4096}\}"
    ),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bsk_live_[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?im)^PuTTY-User-Key-File-\d+\s*:"),
    re.compile(r"(?im)^Private-Lines\s*:\s*\d+"),
    re.compile(r"\bAGE-SECRET-KEY-1[A-Z0-9-]{8,}\b"),
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
    return (
        any(
            any(name in part.casefold() for name in SENSITIVE_NAMES)
            or any(pattern.search(part) for pattern in SENSITIVE_NAME_PATTERNS)
            for part in path.parts
        )
        or path.suffix.casefold() in SENSITIVE_SUFFIXES
    )


def _is_text(text: str) -> bool:
    return not any(
        (ord(character) < 32 and character not in "\t\n\r") or ord(character) == 0xFFFD
        for character in text
    )


def _decoded_candidates(content: bytes) -> tuple[str, ...]:
    """Decode UTF text, rejecting undecodable or binary content."""
    if len(content) > MAX_CONTENT_BYTES:
        raise SyncError("refusing content larger than safety limit")
    encodings: list[str] = []
    if content.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encodings.append("utf-32")
    elif content.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings.append("utf-16")
    elif content.startswith(b"\xef\xbb\xbf"):
        encodings.append("utf-8-sig")
    else:
        encodings.append("utf-8")
        if b"\x00" in content:
            encodings.extend(("utf-16", "utf-32"))

    candidates: list[str] = []
    for encoding in encodings:
        try:
            text = content.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _is_text(text) and text not in candidates:
            candidates.append(text)
    if not candidates:
        raise SyncError("refusing undecodable or binary content")
    if b"\x00" in content and not any("\x00" not in text for text in candidates):
        raise SyncError("refusing binary content")
    return tuple(candidates)


def _text_variants(text: str) -> tuple[str, ...]:
    """Add bounded percent- and escape-decoded forms for marker scanning."""
    variants = [text]
    current = text
    for _ in range(2):
        decoded = unquote(current)
        if decoded == current:
            break
        variants.append(decoded)
        current = decoded
    try:
        escaped = codecs.decode(text, "unicode_escape")
    except UnicodeDecodeError:
        escaped = text
    if escaped != text and _is_text(escaped):
        variants.append(escaped)
    return tuple(dict.fromkeys(variants))


def _base64_variants(text: str) -> tuple[str, ...]:
    """Decode bounded contiguous and whitespace-wrapped base64 fragments."""
    contiguous = re.compile(
        r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{8,}={0,2})(?![A-Za-z0-9+/_=-])"
    )
    wrapped = re.compile(
        r"(?<![A-Za-z0-9+/_-])((?:[A-Za-z0-9+/_-]{4}[ \t\r\n]+)+"
        r"[A-Za-z0-9+/_-]{2,4}={0,2})(?![A-Za-z0-9+/_=-])"
    )
    matches = list(contiguous.finditer(text)) + list(wrapped.finditer(text))
    matches.sort(key=lambda match: match.start())
    variants: list[str] = []
    for index, match in enumerate(matches):
        if index >= MAX_BASE64_CANDIDATES:
            raise SyncError("refusing content with too many encoded candidates")
        encoded = re.sub(r"\s+", "", match.group(1))
        if len(encoded) > MAX_BASE64_CHARS:
            raise SyncError("refusing oversized encoded candidate")
        encoded += "=" * (-len(encoded) % 4)
        try:
            decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
        except (ValueError, binascii.Error):
            continue
        if len(decoded) > MAX_BASE64_BYTES:
            raise SyncError("refusing oversized encoded candidate")
        try:
            candidate = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _is_text(candidate):
            variants.append(candidate)
    return tuple(variants)


def ensure_safe_content(content: bytes) -> None:
    """Reject credential formats without exposing file contents."""
    texts = _decoded_candidates(content)
    text_variants = tuple(variant for text in texts for variant in _text_variants(text))
    variants = tuple(
        variant for text in text_variants for variant in (text, *_base64_variants(text))
    )
    if any(marker.search(text) for text in variants for marker in CREDENTIAL_MARKERS):
        raise SyncError("refusing content that resembles a credential")


def _read_bounded_content(path: Path) -> bytes:
    """Read at most one byte beyond the public-repository size limit."""
    try:
        with path.open("rb") as handle:
            content = handle.read(MAX_CONTENT_BYTES + 1)
    except OSError as exc:
        raise SyncError(f"cannot read file: {path}") from exc
    if len(content) > MAX_CONTENT_BYTES:
        raise SyncError(f"refusing content larger than safety limit: {path}")
    return content

def _read_verified_content(path: Path, label: str) -> bytes:
    """Read bounded content, rejecting links, hardlinks, and mid-read changes."""
    before = _regular_file_stat(path, label)
    if before.st_nlink > 1:
        raise SyncError(f"refusing hardlink {label}: {path}")
    content = _read_bounded_content(path)
    try:
        after = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise SyncError(f"{label} changed during read: {path}") from exc
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
    ):
        raise SyncError(f"{label} changed during read: {path}")
    return content


def _reject_symlink_ancestors(path: Path) -> None:
    """Reject symlink roots or parent components before filesystem access."""
    current = path
    while True:
        if current.is_symlink():
            raise SyncError(f"refusing symlink path component: {current}")
        if current == current.parent:
            break
        current = current.parent


def _validated_root(root: Path, label: str) -> Path:
    """Return a canonical directory root, rejecting symlink components."""
    root = Path(root).expanduser()
    _reject_symlink_ancestors(root)
    canonical = root.resolve(strict=False)
    if canonical.exists() and not canonical.is_dir():
        raise SyncError(f"{label} root is not a directory: {root}")
    return canonical


def _reject_symlink_components(root: Path, relative: Path) -> None:
    current = root
    for component in relative.parts:
        current /= component
        if current.is_symlink():
            raise SyncError(f"refusing symlink path component: {current}")


def _safe_join(root: Path, relative_path: str | Path, *, label: str = "root") -> Path:
    relative = Path(relative_path)
    validate_relative_path(relative)
    canonical_root = _validated_root(root, label)
    _reject_symlink_components(canonical_root, relative)
    candidate = (canonical_root / relative).resolve(strict=False)
    try:
        candidate.relative_to(canonical_root)
    except ValueError as exc:
        raise SyncError(f"path escapes {label}: {relative}") from exc
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
    return _safe_join(base, relative_path, label="destination")


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


def _reject_symlink_path(path: Path) -> None:
    """Reject a symlink file or any symlink parent before I/O."""
    _reject_symlink_ancestors(Path(path))


def _regular_file_stat(path: Path, label: str) -> os.stat_result:
    """Stat a non-symlink regular file without following links."""
    try:
        details = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise SyncError(f"{label} file not found: {path}") from exc
    if not stat.S_ISREG(details.st_mode):
        raise SyncError(f"{label} is not a regular file: {path}")
    return details


def _copy_atomically(
    source: Path, destination: Path, content: bytes, *, force: bool
) -> None:
    """Write a sibling temporary file, then atomically publish it."""
    parent = destination.parent
    _reject_symlink_path(parent)
    parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_path(parent)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=parent, prefix=f".{destination.name}.", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        shutil.copystat(source, temporary, follow_symlinks=False)
        if force:
            os.replace(temporary, destination)
        else:
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise SyncError(
                    f"destination exists; use --force: {destination}"
                ) from exc
            finally:
                if temporary.exists():
                    temporary.unlink()
            temporary = None
    finally:
        if temporary is not None:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()


def copy_file(
    source: Path,
    destination: Path,
    *,
    dry_run: bool,
    force: bool,
) -> None:
    """Validate and copy one file, preserving existing destinations by default.

    Atomic replacement plus no-follow checks limit races. Full descriptor-relative
    no-follow copying is not portable through Python's standard library.
    """
    _reject_symlink_path(source)
    _reject_symlink_path(destination)
    if is_sensitive_path(source) or is_sensitive_path(destination):
        raise SyncError(f"refusing sensitive path: {source}")
    source_stat = _regular_file_stat(source, "source")
    if source_stat.st_nlink > 1:
        raise SyncError(f"refusing hardlink source: {source}")
    if destination.exists():
        destination_stat = _regular_file_stat(destination, "destination")
        if destination_stat.st_nlink > 1:
            raise SyncError(f"refusing hardlink destination: {destination}")
        if not force:
            raise SyncError(f"destination exists; use --force: {destination}")
    content = _read_bounded_content(source)
    ensure_safe_content(content)
    try:
        current_stat = os.stat(source, follow_symlinks=False)
    except OSError as exc:
        raise SyncError(f"source changed during read: {source}") from exc
    if (
        current_stat.st_dev != source_stat.st_dev
        or current_stat.st_ino != source_stat.st_ino
        or current_stat.st_size != source_stat.st_size
        or current_stat.st_mtime_ns != source_stat.st_mtime_ns
    ):
        raise SyncError(f"source changed during read: {source}")
    action = "would copy" if dry_run else "copy"
    print(f"{action} {source} -> {destination}")
    if not dry_run:
        _copy_atomically(source, destination, content, force=force)


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
    repo_root = _validated_root(repo_root, "repository")
    home, appdata = _defaults(platform, home, appdata)
    count = 0
    for item in entries:
        source = resolve_destination(
            platform, item.platform_root, item.relative_path, home=home, appdata=appdata
        )
        destination = _safe_join(repo_root, item.repo_path, label="repository")
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
    repo_root = _validated_root(repo_root, "repository")
    home, appdata = _defaults(platform, home, appdata)
    count = 0
    for item in entries:
        source = _safe_join(repo_root, item.repo_path, label="repository")
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
    repo_root = _validated_root(repo_root, "repository")
    home, appdata = _defaults(platform, home, appdata)
    failures = 0
    for item in entries:
        source = resolve_destination(
            platform, item.platform_root, item.relative_path, home=home, appdata=appdata
        )
        repo_file = _safe_join(repo_root, item.repo_path, label="repository")
        for label, path in (("source", source), ("repo", repo_file)):
            if path.exists():
                try:
                    ensure_safe_content(_read_verified_content(path, label))
                except (OSError, SyncError) as exc:
                    print(f"unsafe {label} {path}: {exc}")
                    failures += 1
                else:
                    print(f"ok {label} {path}")
            elif path.is_symlink():
                print(f"unsafe {label} {path}: dangling symlink")
                failures += 1
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
            install_files(MANIFEST, repo_root, dry_run=args.dry_run, force=args.force)
        else:
            return check_files(MANIFEST, repo_root)
    except (KeyError, OSError, SyncError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
