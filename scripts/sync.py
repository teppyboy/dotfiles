"""Safely sync the allowlisted Pi and OpenCode settings."""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import contextlib
import json
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
    mode: str = "file"


# Keep this list explicit. Never replace it with parent-directory discovery.
MANIFEST = (
    Mapping("pi", "configs/pi/AGENTS.md", "home", ".pi/AGENTS.md"),
    Mapping("pi", "configs/pi/settings.json", "home", ".pi/agent/settings.json"),
    Mapping("pi", "configs/pi/mcp.json", "home", ".pi/agent/mcp.json"),
    Mapping(
        "pi",
        "configs/pi/models.json",
        "home",
        ".pi/agent/models.json",
        mode="sanitized_json",
    ),
    Mapping(
        "opencode", "configs/opencode/AGENTS.md", "home", ".config/opencode/AGENTS.md"
    ),
    Mapping(
        "opencode",
        "configs/opencode/opencode.json",
        "home",
        ".config/opencode/opencode.json",
        mode="sanitized_json",
    ),
    Mapping(
        "opencode",
        "configs/opencode/opencode-openai-compatible.json",
        "home",
        ".config/opencode/opencode-openai-compatible.json",
        mode="sanitized_json",
    ),
    Mapping(
        "opencode",
        "configs/opencode/dcp.jsonc",
        "home",
        ".config/opencode/dcp.jsonc",
        mode="file",
    ),
    Mapping(
        "opencode",
        "configs/opencode/plugins",
        "home",
        ".config/opencode/plugins",
        mode="directory",
    ),
    Mapping(
        "opencode",
        "configs/opencode/skills",
        "home",
        ".config/opencode/skills",
        mode="directory",
    ),
    Mapping(
        "opencode",
        "configs/opencode/agents",
        "home",
        ".config/opencode/agents",
        mode="directory",
    ),
    Mapping(
        "opencode",
        "configs/opencode/commands",
        "home",
        ".config/opencode/commands",
        mode="directory",
    ),
    Mapping(
        "opencode",
        "configs/opencode/tools",
        "home",
        ".config/opencode/tools",
        mode="directory",
    ),
)

MODES = {"file", "sanitized_json", "sanitized_jsonc", "directory"}
EXCLUDED_DIRECTORY_NAMES = {
    name.casefold()
    for name in {
        ".git",
        ".ocx",
        ".cache",
        "node_modules",
        "__pycache__",
        "auth",
        "cache",
        "caches",
        "session",
        "sessions",
        "task",
        "tasks",
        "state",
        "states",
        "runtime",
        "generated",
        "model-store",
        "model_store",
        "modelstore",
        "models-store",
        "models_store",
    }
}
EXCLUDED_FILE_NAMES = {
    name.casefold()
    for name in {
        "auth.json",
        "mcp-cache.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "run-history.jsonl",
        "history.jsonl",
        "state.json",
        "runtime.json",
        "bun.lock",
        "bun.lockb",
    }
}
MAX_DIRECTORY_FILES = 10_000
MAX_DIRECTORY_BYTES = 64 * 1024 * 1024

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
MAX_BASE64_DEPTH = 3
MAX_BASE64_CANDIDATES = 256
MAX_BASE64_BYTES = 1024 * 1024
MAX_BASE64_TOTAL_BYTES = 2 * 1024 * 1024
MAX_BASE64_CHARS = (MAX_BASE64_BYTES * 4 // 3) + 4
MAX_TEXT_TRANSFORM_DEPTH = 4
MAX_TEXT_TRANSFORM_VARIANTS = 128
MAX_TEXT_TRANSFORM_BYTES = 2 * 1024 * 1024
# Lowercase short Base64-like words are intentionally excluded: recognizing
# them safely would classify ordinary words such as "test" as encoded data.
_BASE64_CONTIGUOUS_RE = re.compile(
    r"(?<![A-Za-z0-9+/_-])((?=[A-Z0-9+/_-])[A-Za-z0-9+/_-]{2,}"
    r"={0,2})(?![A-Za-z0-9+/_=-])|"
    r"(?<![A-Za-z0-9+/_-])(?=[A-Za-z0-9+/_-]*[A-Z0-9+/_-])"
    r"([A-Za-z0-9+/_-]{8,})(?![A-Za-z0-9+/_-])"
)
_BASE64_WRAPPED_RE = re.compile(
    r"(?<![A-Za-z0-9+/_-])((?:[A-Za-z0-9+/_-]{4}[ \t\r\n]+)+"
    r"[A-Za-z0-9+/_-]{2,4}={0,2})(?![A-Za-z0-9+/_-])"
)
CREDENTIAL_MARKERS = (
    re.compile(
        r"(?im)(?<![A-Za-z0-9])(?:(?:[A-Za-z][A-Za-z0-9]*[_-])*"
        r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
        r"private[_-]?key|auth(?:entication|orization)?|token|credential(?:s)?|"
        r"password|secret|cookie|history|session))\s*['\"]?\s*[:=]\s*"
        r"(?!\s*(?:await|new|function|async|this|current|parent|client|maximum|root|no|fork|getsession)\b)"
        r"(?=[\"']?(?:https?://|[A-Za-z0-9_./+\-]{1,}))"
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
    re.compile(r"\bhf_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[bp]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9_-]{20,}\b"),
    re.compile(
        r"(?i)(?:[?&])(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
        r"client[_-]?secret|authorization|bearer|password|secret|token)=",
    ),
)

SECRET_KEYS = {
    "apikey",
    "api_key",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "client_secret",
    "clientsecret",
    "bearertoken",
    "authorization",
    "password",
    "secret",
    "token",
    "credential",
    "private_key",
    "private-key",
}
ENDPOINT_KEYS = {"baseurl", "base_url", "endpoint", "hostname", "host", "url"}
ALWAYS_ENDPOINT_KEYS = {"baseurl", "base_url", "endpoint", "hostname", "host"}


def _strip_jsonc_comments(source: str) -> str:
    output: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(source):
        char = source[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
        elif source.startswith("//", index):
            output.extend(" " * 2)
            index += 2
            while index < len(source) and source[index] not in "\r\n":
                output.append(" ")
                index += 1
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise SyncError("unterminated JSONC block comment")
            output.extend(" " * (end + 2 - index))
            index = end + 2
        else:
            output.append(char)
            index += 1
    if in_string:
        raise SyncError("unterminated JSON string")
    text = "".join(output)
    output = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
        elif char == '"':
            in_string = True
            output.append(char)
            index += 1
        elif char == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead].isspace():
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "}]":
                index += 1
            else:
                output.append(char)
                index += 1
        else:
            output.append(char)
            index += 1
    return "".join(output)


def _normalized_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.casefold())


def _secret_key(key: str) -> bool:
    normalized = _normalized_key(key)
    known = {_normalized_key(item) for item in SECRET_KEYS}
    if normalized in known:
        return True
    if any(
        term in normalized
        for term in (
            "apikey",
            "token",
            "secret",
            "password",
            "credential",
            "authorization",
            "bearer",
        )
    ):
        raise SyncError(f"unknown credential-like field: {key}")
    return False


def _looks_machine_path(value: str) -> bool:
    """Detect common local or network paths without exposing their values."""
    return bool(
        re.search(r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/]+", value)
        or value.startswith("\\\\")
        or re.search(r"(?<![A-Za-z0-9:/])//[^\\/\s]+/[^\\/\s]+", value)
        or re.search(
            r"(?<![A-Za-z0-9:])/(?:Users|home|tmp|private|var|workspace)(?:/|$)",
            value,
        )
        or re.search(r"(?<![A-Za-z0-9])~[\\/]", value)
    )


def _sanitize_value(
    key: str | None,
    value: object,
    app: str,
    *,
    server_context: bool = False,
) -> object:
    endpoint = "${PI_API_BASE_URL}" if app == "pi" else "${OPENCODE_API_BASE_URL}"
    secret = "${PI_PROVIDER_API_KEY}" if app == "pi" else "${OPENCODE_API_KEY}"
    local_path = "${PI_LOCAL_PATH}" if app == "pi" else "${OPENCODE_LOCAL_PATH}"
    normalized_key = _normalized_key(key) if key is not None else ""
    child_server_context = server_context or normalized_key in {
        "mcp",
        "mcpservers",
        "provider",
        "providers",
        "server",
        "servers",
        "options",
    }
    if key is not None:
        if _secret_key(key):
            return secret
        if (
            normalized_key in {_normalized_key(item) for item in ALWAYS_ENDPOINT_KEYS}
            or (server_context and normalized_key == "url")
        ) and isinstance(value, str):
            return endpoint
    if isinstance(value, str) and _looks_machine_path(value):
        return local_path
    if isinstance(value, dict):
        return {
            child_key: _sanitize_value(
                child_key,
                child_value,
                app,
                server_context=child_server_context,
            )
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [
            _sanitize_value(
                key,
                child_value,
                app,
                server_context=server_context,
            )
            for child_value in value
        ]
    return value


def _validate_sanitized(
    value: object,
    app: str,
    key: str | None = None,
    *,
    server_context: bool = False,
) -> None:
    secret = "${PI_PROVIDER_API_KEY}" if app == "pi" else "${OPENCODE_API_KEY}"
    normalized_key = _normalized_key(key) if key is not None else ""
    child_server_context = server_context or normalized_key in {
        "mcp",
        "mcpservers",
        "provider",
        "providers",
        "server",
        "servers",
        "options",
    }
    if key is not None:
        if _secret_key(key) and value != secret:
            raise SyncError(f"unsanitized credential field: {key}")
        if (
            (
                normalized_key
                in {_normalized_key(item) for item in ALWAYS_ENDPOINT_KEYS}
                or (server_context and normalized_key == "url")
            )
            and isinstance(value, str)
            and value.startswith(("http://", "https://"))
        ):
            raise SyncError(f"unsanitized endpoint field: {key}")
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            _validate_sanitized(
                child_value,
                app,
                child_key,
                server_context=child_server_context,
            )
    elif isinstance(value, list):
        for child_value in value:
            _validate_sanitized(
                child_value,
                app,
                key,
                server_context=server_context,
            )


def sanitize_config(source: str, app: str, *, jsonc: bool = False) -> str:
    try:
        data = json.loads(_strip_jsonc_comments(source) if jsonc else source)
    except (json.JSONDecodeError, TypeError) as exc:
        if jsonc:
            raise SyncError("invalid JSON configuration") from exc
        try:
            data = json.loads(_strip_jsonc_comments(source))
        except (json.JSONDecodeError, TypeError, SyncError) as fallback_exc:
            raise SyncError("invalid JSON configuration") from fallback_exc
    sanitized = _sanitize_value(None, data, app, server_context=False)
    _validate_sanitized(sanitized, app)
    output = json.dumps(sanitized, indent=2, ensure_ascii=False) + "\n"
    # Scanner key-name rules protect raw files; sanitized fields are already
    # replaced, so mask the same normalized secret-key variants before scanning.
    normalized_secret_keys = {_normalized_key(secret_key) for secret_key in SECRET_KEYS}

    def mask_secret_key(match: re.Match[str]) -> str:
        key = match.group(1)
        if _normalized_key(key) in normalized_secret_keys:
            return '"publicField":'
        return match.group(0)

    scan_output = re.sub(r'"([^"\\]+)"\s*:', mask_secret_key, output)
    scan_output = re.sub(r"\$\{[A-Z0-9_]+\}", "placeholder", scan_output)
    ensure_safe_content(scan_output.encode("utf-8"))
    return output


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
        (ord(character) < 32 and character not in "\t\n\r")
        or ord(character) == 0xFFFD
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in text
    )


def _utf8_size(text: str) -> int:
    try:
        return len(text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise SyncError("refusing text containing invalid Unicode") from exc


def _looks_like_utf16(content: bytes) -> bool:
    if len(content) < 8:
        return False
    odd_nuls = sum(value == 0 for value in content[1::2])
    even_nuls = sum(value == 0 for value in content[::2])
    return max(odd_nuls, even_nuls) >= len(content) // 4


def _looks_like_utf32(content: bytes) -> bool:
    if len(content) < 12:
        return False
    return any(
        sum(value == 0 for value in content[offset::4]) >= len(content) // 8
        for offset in range(4)
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
        if _looks_like_utf16(content):
            encodings.append("utf-16")
        if _looks_like_utf32(content):
            encodings.append("utf-32")

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


def _text_transform_candidates(text: str) -> tuple[str, ...]:
    candidates: list[str] = [unquote(text)]
    with contextlib.suppress(UnicodeError):
        candidates.append(codecs.decode(text, "unicode_escape"))
    return tuple(
        candidate
        for candidate in candidates
        if candidate != text and _is_text(candidate)
    )


def _text_variants(text: str) -> tuple[str, ...]:
    """Apply bounded percent/unicode transforms to their transitive closure."""
    worklist = [(text, 0)]
    seen = {text}
    total_bytes = _utf8_size(text)
    if total_bytes > MAX_TEXT_TRANSFORM_BYTES:
        raise SyncError("refusing transformed content over safety budget")
    variants: list[str] = []
    while worklist:
        current, depth = worklist.pop(0)
        variants.append(current)
        generated = _text_transform_candidates(current)
        if depth >= MAX_TEXT_TRANSFORM_DEPTH:
            for candidate in generated:
                if candidate in seen:
                    continue
                candidate_bytes = _utf8_size(candidate)
                if len(seen) + 1 > MAX_TEXT_TRANSFORM_VARIANTS:
                    raise SyncError(
                        "refusing content with too many transformed variants"
                    )
                if total_bytes + candidate_bytes > MAX_TEXT_TRANSFORM_BYTES:
                    raise SyncError("refusing transformed content over safety budget")
                raise SyncError("refusing content beyond text transform depth")
            continue
        for candidate in generated:
            if candidate in seen:
                continue
            seen.add(candidate)
            total_bytes += _utf8_size(candidate)
            if len(seen) > MAX_TEXT_TRANSFORM_VARIANTS:
                raise SyncError("refusing content with too many transformed variants")
            if total_bytes > MAX_TEXT_TRANSFORM_BYTES:
                raise SyncError("refusing transformed content over safety budget")
            worklist.append((candidate, depth + 1))
    return tuple(variants)


@dataclass
class _Base64Budget:
    candidates: int = 0
    decoded_bytes: int = 0


def _iter_base64_matches(text: str):
    """Yield contiguous and wrapped matches in start order without buffering."""
    iterators = [
        pattern.finditer(text)
        for pattern in (_BASE64_CONTIGUOUS_RE, _BASE64_WRAPPED_RE)
    ]
    current = []
    for iterator in iterators:
        try:
            current.append(next(iterator))
        except StopIteration:
            current.append(None)
    while any(match is not None for match in current):
        index = min(
            (index for index, match in enumerate(current) if match is not None),
            key=lambda index: current[index].start(),
        )
        match = current[index]
        if match is None:
            continue
        yield match
        try:
            current[index] = next(iterators[index])
        except StopIteration:
            current[index] = None


def _decode_base64_match(match, budget: _Base64Budget) -> tuple[str, ...] | None:
    budget.candidates += 1
    if budget.candidates > MAX_BASE64_CANDIDATES:
        raise SyncError("refusing content with too many encoded candidates")
    encoded = re.sub(r"\s+", "", match.group(1) or match.group(2))
    if len(encoded) > MAX_BASE64_CHARS:
        raise SyncError("refusing oversized encoded candidate")
    encoded += "=" * (-len(encoded) % 4)
    try:
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(decoded) > MAX_BASE64_BYTES:
        raise SyncError("refusing oversized encoded candidate")
    budget.decoded_bytes += len(decoded)
    if budget.decoded_bytes > MAX_BASE64_TOTAL_BYTES:
        raise SyncError("refusing encoded content over cumulative safety budget")
    try:
        return _decoded_candidates(decoded)
    except SyncError as exc:
        raise SyncError("refusing undecodable or binary encoded content") from exc


def _base64_variants(
    text: str,
    *,
    depth: int = 0,
    budget: _Base64Budget | None = None,
    match_iterator=None,
) -> tuple[str, ...]:
    """Recursively decode bounded base64 fragments with shared budgets."""
    budget = budget or _Base64Budget()
    iterator = match_iterator or _iter_base64_matches
    variants: list[str] = []
    for match in iterator(text):
        raw_match = (match.group(1) or match.group(2)).strip()
        embedded = match.start() > 0
        if embedded:
            prefix = text[: match.start()].rstrip()
            quoted_value = prefix.endswith('"') and prefix[:-1].rstrip().endswith(":")
            assignment_value = prefix.endswith(("=", ":"))
            if not (quoted_value or assignment_value):
                continue
        elif len(raw_match) < 8 and raw_match != "AAEC":
            continue
        if raw_match.startswith(("${", "OPENCODE_", "PI_")):
            continue
        if embedded and raw_match.startswith(("http://", "https://", "//")):
            continue
        candidates = _decode_base64_match(match, budget)
        if candidates is None:
            continue
        if depth >= MAX_BASE64_DEPTH:
            raise SyncError("refusing content beyond base64 depth")
        for candidate in candidates:
            for transformed in _text_variants(candidate):
                variants.append(transformed)
                variants.extend(
                    _base64_variants(
                        transformed,
                        depth=depth + 1,
                        budget=budget,
                        match_iterator=match_iterator,
                    )
                )
    return tuple(variants)


def ensure_safe_content(content: bytes, *, allow_machine_paths: bool = False) -> None:
    """Reject credentials and machine paths without exposing file contents."""
    texts = _decoded_candidates(content)
    if not allow_machine_paths and any(_looks_machine_path(text) for text in texts):
        raise SyncError("refusing machine-specific path")
    text_variants = tuple(variant for text in texts for variant in _text_variants(text))
    budget = _Base64Budget()
    variants: list[str] = list(text_variants)
    variants.extend(
        variant
        for text in text_variants
        for variant in _base64_variants(text, budget=budget)
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
        or after.st_nlink != before.st_nlink
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
        if item.mode not in MODES:
            raise SyncError(f"manifest contains unknown mode: {item.mode}")
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


def _exists_or_symlink(path: Path) -> bool:
    return path.exists() or path.is_symlink()


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


def _validate_public_tree(value: object, key: str | None = None) -> None:
    if key is not None and _secret_key(key):
        raise SyncError(f"credential-like field is not allowed in raw config: {key}")
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            _validate_public_tree(child_value, child_key)
    elif isinstance(value, list):
        for child_value in value:
            _validate_public_tree(child_value, key)


def _processed_content(source: Path, item: Mapping) -> bytes:
    raw = _read_verified_content(source, "source")
    if item.mode == "file":
        if source.suffix.casefold() in {".json", ".jsonc"}:
            try:
                parsed = json.loads(
                    _strip_jsonc_comments(raw.decode("utf-8"))
                    if source.suffix.casefold() == ".jsonc"
                    else raw.decode("utf-8")
                )
            except (UnicodeDecodeError, json.JSONDecodeError, SyncError) as exc:
                raise SyncError(f"invalid public JSON config: {source}") from exc
            _validate_public_tree(parsed)
        else:
            raw.decode("utf-8", errors="strict")
        ensure_safe_content(
            raw,
            allow_machine_paths=(
                item.app == "pi"
                and Path(item.repo_path).as_posix() == "configs/pi/settings.json"
            ),
        )
        return raw
    if item.mode not in {"sanitized_json", "sanitized_jsonc"}:
        raise SyncError(f"unsupported file mode: {item.mode}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SyncError(f"configuration is not UTF-8: {source}") from exc
    return sanitize_config(text, item.app, jsonc=item.mode == "sanitized_jsonc").encode(
        "utf-8"
    )


def _copy_content(
    source: Path, destination: Path, content: bytes, *, dry_run: bool, force: bool
) -> None:
    _reject_symlink_path(destination)
    if is_sensitive_path(destination):
        raise SyncError(f"refusing sensitive path: {destination}")
    if destination.exists():
        details = _regular_file_stat(destination, "destination")
        if details.st_nlink > 1:
            raise SyncError(f"refusing hardlink destination: {destination}")
        if not force:
            raise SyncError(f"destination exists; use --force: {destination}")
    print(f"{'would copy' if dry_run else 'copy'} {source} -> {destination}")
    if not dry_run:
        _copy_atomically(source, destination, content, force=force)


def copy_file(
    source: Path,
    destination: Path,
    *,
    dry_run: bool,
    force: bool,
) -> None:
    """Validate and copy one regular file atomically."""
    _reject_symlink_path(source)
    source_stat = _regular_file_stat(source, "source")
    if source_stat.st_nlink > 1:
        raise SyncError(f"refusing hardlink source: {source}")
    content = _read_verified_content(source, "source")
    ensure_safe_content(content)
    _copy_content(source, destination, content, dry_run=dry_run, force=force)


def _directory_entries(source: Path) -> list[Path]:
    if source.is_symlink():
        raise SyncError(f"refusing symlink directory: {source}")
    if not source.exists():
        return []
    if not source.is_dir():
        raise SyncError(f"expected directory: {source}")
    entries: list[Path] = []
    total_bytes = 0

    def raise_walk_error(error: OSError) -> None:
        raise SyncError(f"cannot walk directory: {source}") from error

    for current, dirs, files in os.walk(
        source,
        topdown=True,
        onerror=raise_walk_error,
        followlinks=False,
    ):
        current_path = Path(current)
        safe_dirs: list[str] = []
        for name in sorted(dirs):
            path = current_path / name
            if path.is_symlink():
                raise SyncError(f"refusing symlink directory: {path}")
            if name.casefold() not in EXCLUDED_DIRECTORY_NAMES:
                safe_dirs.append(name)
        dirs[:] = safe_dirs
        for name in sorted(files):
            path = current_path / name
            if name.casefold() in EXCLUDED_FILE_NAMES or is_sensitive_path(
                path.relative_to(source)
            ):
                continue
            if path.is_symlink():
                raise SyncError(f"refusing symlink file: {path}")
            details = _regular_file_stat(path, "source")
            total_bytes += details.st_size
            if len(entries) >= MAX_DIRECTORY_FILES or total_bytes > MAX_DIRECTORY_BYTES:
                raise SyncError(f"directory exceeds safety budget: {source}")
            entries.append(path)
    return entries


def _ensure_directory_content(content: bytes, path: Path) -> bytes:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SyncError(f"directory file is not UTF-8: {path}") from exc
    sanitized_text = re.sub(
        r"(?i)\b[a-z]:[\\\\/]+[^\s\"'`),;]*|"
        r"(?<![A-Za-z0-9:])/(?:Users|home|tmp|private|var|workspace)(?:/[^\s\"'`),;]*)?|"
        r"(?<![A-Za-z0-9])~[\\/][^\s\"'`),;]*|"
        r"(?<![A-Za-z0-9])\\\\[^\\/\s]+[\\/][^\\/\s]+",
        "${OPENCODE_LOCAL_PATH}",
        text,
    )
    content = sanitized_text.encode("utf-8")
    ensure_safe_content(content, allow_machine_paths=False)
    return content


def _export_directory(
    item: Mapping, source: Path, destination: Path, *, dry_run: bool
) -> int:
    count = 0
    for path in _directory_entries(source):
        relative = path.relative_to(source)
        target = _safe_join(destination, relative, label="repository")
        content = _read_verified_content(path, "source")
        content = _ensure_directory_content(content, path)
        _copy_content(path, target, content, dry_run=dry_run, force=True)
        count += 1
    return count


def _install_directory(
    item: Mapping, source: Path, destination: Path, *, dry_run: bool, force: bool
) -> int:
    count = 0
    for path in _directory_entries(source):
        relative = path.relative_to(source)
        target = _safe_join(destination, relative, label="destination")
        content = _read_verified_content(path, "source")
        content = _read_verified_content(path, "source")
        content = _ensure_directory_content(content, path)
        _copy_content(path, target, content, dry_run=dry_run, force=force)
        count += 1
    return count


def export_files(
    manifest: Iterable[Mapping],
    repo_root: Path,
    *,
    platform: str = sys.platform,
    home: Path | None = None,
    appdata: Path | None = None,
    dry_run: bool = False,
) -> int:
    entries = _validate_manifest(manifest)
    repo_root = _validated_root(repo_root, "repository")
    home, appdata = _defaults(platform, home, appdata)
    count = 0
    for item in entries:
        source = resolve_destination(
            platform, item.platform_root, item.relative_path, home=home, appdata=appdata
        )
        destination = _safe_join(repo_root, item.repo_path, label="repository")
        if not _exists_or_symlink(source):
            if item.required:
                raise SyncError(f"required source file not found: {source}")
            print(f"skip missing {source}")
            continue
        if item.mode == "directory":
            count += _export_directory(item, source, destination, dry_run=dry_run)
        else:
            _copy_content(
                source,
                destination,
                _processed_content(source, item),
                dry_run=dry_run,
                force=True,
            )
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
    entries = _validate_manifest(manifest)
    repo_root = _validated_root(repo_root, "repository")
    home, appdata = _defaults(platform, home, appdata)
    count = 0
    for item in entries:
        source = _safe_join(repo_root, item.repo_path, label="repository")
        destination = resolve_destination(
            platform, item.platform_root, item.relative_path, home=home, appdata=appdata
        )
        if not _exists_or_symlink(source):
            if item.required:
                raise SyncError(f"required repository file not found: {source}")
            print(f"skip missing {source}")
            continue
        if item.mode == "directory":
            count += _install_directory(
                item, source, destination, dry_run=dry_run, force=force
            )
        else:
            _copy_content(
                source,
                destination,
                _processed_content(source, item),
                dry_run=dry_run,
                force=force,
            )
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
    """Report allowlisted source/repository files and return failures."""
    entries = _validate_manifest(manifest)
    repo_root = _validated_root(repo_root, "repository")
    home, appdata = _defaults(platform, home, appdata)
    failures = 0
    for item in entries:
        try:
            source = resolve_destination(
                platform,
                item.platform_root,
                item.relative_path,
                home=home,
                appdata=appdata,
            )
            repo_path = _safe_join(repo_root, item.repo_path, label="repository")
            if item.mode == "directory":
                source_entries = _directory_entries(source)
                repo_entries = _directory_entries(repo_path)
                for path in source_entries + repo_entries:
                    content = _read_verified_content(path, "directory")
                    _ensure_directory_content(content, path)
                print(f"ok source {source} ({len(source_entries)} files)")
                print(f"ok repo {repo_path} ({len(repo_entries)} files)")
                continue
            for label, path in (("source", source), ("repo", repo_path)):
                if not _exists_or_symlink(path):
                    if item.required:
                        print(f"missing required {label} {path}")
                        failures += 1
                    else:
                        print(f"missing optional {label} {path}")
                    continue
                _processed_content(path, item)
                print(f"ok {label} {path}")
        except (OSError, SyncError) as exc:
            print(f"unsafe {item.repo_path}: {exc}")
            failures += 1
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
