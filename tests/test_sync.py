from __future__ import annotations

import base64
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "sync.py"
spec = importlib.util.spec_from_file_location("sync", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load {MODULE_PATH}")
sync = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = sync
spec.loader.exec_module(sync)


class SyncTests(unittest.TestCase):
    def test_resolve_destination_supports_windows_home_and_appdata(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            appdata = root / "appdata"

            self.assertEqual(
                sync.resolve_destination(
                    "win32", "home", ".pi/AGENTS.md", home=home, appdata=appdata
                ),
                (home / ".pi" / "AGENTS.md").resolve(strict=False),
            )
            self.assertEqual(
                sync.resolve_destination(
                    "win32",
                    "appdata",
                    "OpenCode/config.json",
                    home=home,
                    appdata=appdata,
                ),
                (appdata / "OpenCode" / "config.json").resolve(strict=False),
            )

    def test_resolve_destination_supports_macos_home(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            self.assertEqual(
                sync.resolve_destination(
                    "darwin", "home", ".pi/AGENTS.md", home=home, appdata=None
                ),
                (home / ".pi" / "AGENTS.md").resolve(strict=False),
            )

    def test_unsupported_platform_fails(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(sync.SyncError):
            sync.resolve_destination(
                "linux", "home", "settings.toml", home=Path(temp), appdata=None
            )

    def test_unsupported_root_fails(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(sync.SyncError):
            sync.resolve_destination(
                "darwin", "appdata", "settings.toml", home=Path(temp), appdata=None
            )

    def test_manifest_rejects_absolute_and_traversal_paths(self):
        with self.assertRaises(sync.SyncError):
            sync.validate_relative_path(Path("/absolute/path"))
        with self.assertRaises(sync.SyncError):
            sync.validate_relative_path(Path("../secret"))

    def test_gitignore_matches_sensitive_path_policy(self):
        gitignore = (MODULE_PATH.parents[1] / ".gitignore").read_text(encoding="utf-8")
        for path in (
            ".env",
            "private/private.json",
            "keyring.json",
            "wallet.json",
            "api_key.json",
        ):
            self.assertTrue(sync.is_sensitive_path(Path(path)))
        for pattern in (
            ".env",
            "**/*private*",
            "**/*keyring*",
            "**/*wallet*",
            "**/*api_key*",
            "**/*api-key*",
            "**/*apikey*",
            "**/private.json",
        ):
            self.assertIn(pattern, gitignore)

    def test_duplicate_manifest_paths_are_rejected(self):
        item = sync.Mapping("test", "same.txt", "home", "one.txt")
        duplicate = sync.Mapping("test", "same.txt", "home", "two.txt")
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(sync.SyncError):
            sync.check_files(
                (item, duplicate), Path(temp), platform="darwin", home=Path(temp)
            )

    def test_manifest_paths_are_safe(self):
        for item in sync.MANIFEST:
            with self.subTest(item=item):
                sync.validate_relative_path(Path(item.repo_path))
                sync.validate_relative_path(Path(item.relative_path))
                self.assertFalse(sync.is_sensitive_path(Path(item.repo_path)))
                self.assertFalse(sync.is_sensitive_path(Path(item.relative_path)))

    def test_sensitive_paths_are_rejected(self):
        for path in (
            Path("configs/opencode/auth.json"),
            Path("configs/opencode/_auth.json"),
            Path("configs/pi/_TOKEN"),
            Path("configs/pi/__API_KEY"),
            Path("configs/pi/session.json"),
            Path("configs/pi/private.key"),
            Path("configs/pi/private_key"),
            Path("configs/pi/private-key"),
            Path("configs/pi/id_rsa"),
            Path("configs/pi/id_dsa"),
            Path("configs/pi/id_ecdsa"),
            Path("configs/pi/id_ed25519"),
            Path("configs/pi/private.asc"),
            Path("configs/pi/private.gpg"),
            Path("configs/pi/private.ppk"),
            Path("configs/pi/private.p8"),
            Path("configs/pi/private.jks"),
            Path("configs/pi/private.jceks"),
            Path("configs/pi/private.keystore"),
            Path("configs/pi/.env"),
            Path("configs/pi/.env.local"),
            Path("configs/pi/private/private.json"),
            Path("configs/pi/keyring.json"),
            Path("configs/pi/wallet.json"),
            Path("configs/pi/api_key.json"),
            Path("configs/pi/api-key.json"),
            Path("configs/pi/apikey.json"),
        ):
            with self.subTest(path=path):
                self.assertTrue(sync.is_sensitive_path(path))

    def test_content_scanner_rejects_credential_markers(self):
        for content in (
            b'api_key = "abc"',
            b"access-token: abc",
            b'private_key = "abc"',
            b"password: abc",
            b"token = abc",
            b"auth = abc",
            b"credential: abc",
            b"cookie = abc",
            b"session: abc",
            b'{"token": "abc"}',
            b'{"api_key": "abc"}',
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            b'{"d": "private-material"}',
            b"_TOKEN = abc",
            b"__API_KEY = abc",
            b"OPENAI_API_KEY = abc",
            b"MY_PASSWORD: abc",
            b"sk_live_1234567890123456",
            b"AIzaSyA123456789012345678901234567890",
            b"ASIA1234567890ABCDEF",
            b"PuTTY-User-Key-File-2: ssh-rsa",
            b"Private-Lines: 6",
            b"AGE-SECRET-KEY-1QQQQQQQQ",
            b'{"kty": "oct", "k": "symmetric-material"}',
            b'{"k": "symmetric-material", "kty": "OKP"}',
            b"hf_12345678901234567890",
            b"xoxb-12345678901234567890",
            b"xoxp-12345678901234567890",
            b"glpat-12345678901234567890",
            b"npm_12345678901234567890",
        ):
            with self.subTest(content=content), self.assertRaises(sync.SyncError):
                sync.ensure_safe_content(content)

    def test_content_scanner_rejects_utf16_and_utf32_credentials(self):
        for encoding in ("utf-16", "utf-32"):
            with self.subTest(encoding=encoding), self.assertRaises(sync.SyncError):
                sync.ensure_safe_content("token = abc".encode(encoding))

    def test_content_scanner_rejects_binary_content(self):
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(bytes((0, 1, 2)))

    def test_content_scanner_rejects_unpadded_short_binary_base64(self):
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(b"AAEC")

    def test_content_scanner_leaves_lowercase_short_words_unclassified(self):
        sync.ensure_safe_content(b"test")

    def test_text_transform_rejects_deeper_pending_candidate(self):
        encoded = "token=abc"
        for _ in range(sync.MAX_TEXT_TRANSFORM_DEPTH + 1):
            encoded = encoded.replace("%", "%25").replace("=", "%3D")
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(encoded.encode())

    def test_base64_rejects_deeper_pending_candidate(self):
        encoded = b"token=abc"
        for _ in range(sync.MAX_BASE64_DEPTH + 1):
            encoded = base64.b64encode(encoded)
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(encoded)

    def test_text_transform_rejects_oversized_initial_text(self):
        with self.assertRaises(sync.SyncError):
            sync._text_variants("x" * (sync.MAX_TEXT_TRANSFORM_BYTES + 1))

    def test_text_transform_rejects_surrogate_code_points(self):
        self.assertFalse(sync._is_text("bad\ud800"))
        with self.assertRaises(sync.SyncError):
            sync._text_variants("bad\ud800")

    def test_content_scanner_rejects_encoded_credentials(self):
        encoded = base64.b64encode(b"token=abc").decode()
        for content in (
            f"value={encoded}".encode(),
            base64.b64encode(b'{"token": "abc"}'),
            base64.b64encode(b"hf_12345678901234567890"),
            base64.b64encode(b"xoxb-12345678901234567890"),
            base64.b64encode(b"xoxp-12345678901234567890"),
            base64.b64encode(b"glpat-12345678901234567890"),
            base64.b64encode(b"npm_12345678901234567890"),
        ):
            with self.subTest(content=content), self.assertRaises(sync.SyncError):
                sync.ensure_safe_content(content)

    def test_base64_decoded_binary_content_fails_closed(self):
        payload = base64.b64encode(bytes((0, 1, 2, 3)))
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(payload)

    def test_base64_decodes_percent_encoded_credentials(self):
        payload = b"value=OPENAI%5FAPI%5FKEY%3Dabc"
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(base64.b64encode(payload))

    def test_text_transform_closure_rejects_triple_percent_credentials(self):
        payload = b"value=OPENAI%2525255FAPI%2525255FKEY%2525253Dabc"
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(payload)

    def test_text_transform_closure_rejects_mixed_unicode_percent_credentials(self):
        payload = b"value=OPENAI%255Cx5fAPI%255Cx5fKEY%253Dabc"
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(payload)

    def test_base64_wrapped_mixed_transform_credentials_are_rejected(self):
        payload = base64.b64encode(
            b"value=OPENAI%255Cx5fAPI%255Cx5fKEY%253Dabc"
        ).decode()
        wrapped = "\\n".join(
            payload[index : index + 4] for index in range(0, len(payload), 4)
        )
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(f"value={wrapped}".encode())

    def test_base64_decodes_unicode_escaped_credentials(self):
        payload = b"value=OPENAI\\x5fAPI\\x5fKEY=abc"
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(base64.b64encode(payload))

    def test_base64_decodes_utf16_credentials(self):
        payload = "token=abc".encode("utf-16")
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(base64.b64encode(payload))

    def test_content_scanner_rejects_nested_encoded_credentials(self):
        encoded = b"token=abc"
        for _ in range(sync.MAX_BASE64_DEPTH):
            encoded = base64.b64encode(encoded)
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(encoded)

    def test_content_scanner_rejects_encoded_provider_credentials(self):
        for token in (
            b"hf_12345678901234567890",
            b"xoxb-12345678901234567890",
            b"glpat-12345678901234567890",
            b"npm_12345678901234567890",
        ):
            with self.subTest(token=token), self.assertRaises(sync.SyncError):
                sync.ensure_safe_content(base64.b64encode(token))

    def test_content_scanner_rejects_wrapped_and_oversized_encoded_credentials(self):
        short = base64.b64encode(b"token=abc").decode()
        wrapped = "\n".join(
            short[index : index + 4] for index in range(0, len(short), 4)
        )
        oversized = base64.b64encode(
            b"x" * sync.MAX_BASE64_BYTES + b" token=abc"
        ).decode()
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(f"value={wrapped}".encode())
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(f"value={oversized}".encode())

    def test_content_scanner_rejects_private_formats(self):
        for content in (
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            b'{"kty":"oct","k":"abc"}',
        ):
            with self.subTest(content=content), self.assertRaises(sync.SyncError):
                sync.ensure_safe_content(content)

    def test_content_scanner_rejects_oversized_content(self):
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(b"x" * (sync.MAX_CONTENT_BYTES + 1))

    def test_content_scanner_rejects_exhausted_encoded_candidate_budget(self):
        content = b" ".join(
            b"candidate%d" % index for index in range(sync.MAX_BASE64_CANDIDATES + 1)
        )
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(content)

    def test_base64_candidate_iterator_stops_without_materializing_all_matches(self):
        class Match:
            def __init__(self, position):
                self.position = position

            def start(self):
                return self.position

            def group(self, _number):
                return "dGVzdA=="

        pulls = 0

        def bounded_matches(_text):
            nonlocal pulls
            for position in range(10_000_000):
                pulls += 1
                yield Match(position)

        with self.assertRaises(sync.SyncError):
            sync._base64_variants(
                "ignored",
                budget=sync._Base64Budget(),
                match_iterator=bounded_matches,
            )

        self.assertLessEqual(pulls, sync.MAX_BASE64_CANDIDATES + 1)

    def test_bounded_reader_does_not_read_unbounded_content(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "settings.txt"
            path.write_bytes(b"x" * (sync.MAX_CONTENT_BYTES + 1))
            with self.assertRaises(sync.SyncError):
                sync._read_bounded_content(path)

    def test_content_scanner_accepts_non_sensitive_settings(self):
        sync.ensure_safe_content(b"theme = 'dark'\\nmodel = 'default'\\n")

    def test_unlisted_file_is_not_exported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            (home / "listed.md").write_text("safe", encoding="utf-8")
            (home / "unlisted.txt").write_text("also safe", encoding="utf-8")
            manifest = (sync.Mapping("test", "configs/listed.md", "home", "listed.md"),)

            copied = sync.export_files(
                manifest,
                repo,
                platform="darwin",
                home=home,
                appdata=None,
            )

            self.assertEqual(copied, 1)
            self.assertEqual(
                (repo / "configs/listed.md").read_text(encoding="utf-8"), "safe"
            )
            self.assertFalse((repo / "unlisted.txt").exists())

    def test_dry_run_does_not_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            destination = root / "destination.txt"
            source.write_text("safe", encoding="utf-8")

            sync.copy_file(source, destination, dry_run=True, force=False)

            self.assertFalse(destination.exists())

    def test_copy_rejects_directory_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            destination = root / "destination"
            source.write_text("safe", encoding="utf-8")
            destination.mkdir()

            with self.assertRaises(sync.SyncError):
                sync.copy_file(source, destination, dry_run=False, force=True)

    def test_copy_rejects_hardlink_source(self):
        if not hasattr(os, "link"):
            self.skipTest("hardlinks unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            linked = root / "linked.txt"
            destination = root / "destination.txt"
            source.write_text("safe", encoding="utf-8")
            os.link(source, linked)
            with self.assertRaises(sync.SyncError):
                sync.copy_file(linked, destination, dry_run=False, force=True)
            self.assertFalse(destination.exists())

    def test_copy_rejects_hardlink_destination(self):
        if not hasattr(os, "link"):
            self.skipTest("hardlinks unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            destination = root / "destination.txt"
            linked = root / "linked.txt"
            source.write_text("new", encoding="utf-8")
            destination.write_text("old", encoding="utf-8")
            os.link(destination, linked)
            with self.assertRaises(sync.SyncError):
                sync.copy_file(source, destination, dry_run=False, force=True)
            self.assertEqual(destination.read_text(encoding="utf-8"), "old")
            self.assertEqual(linked.read_text(encoding="utf-8"), "old")

    def test_copy_rejects_symlink_source_and_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            source.write_text("safe", encoding="utf-8")
            outside = root / "outside.txt"
            outside.write_text("safe", encoding="utf-8")
            source_link = root / "source-link.txt"
            destination_link = root / "destination-link.txt"
            try:
                source_link.symlink_to(outside)
                destination_link.symlink_to(outside)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks unavailable")

            with self.assertRaises(sync.SyncError):
                sync.copy_file(
                    source_link, root / "copied.txt", dry_run=False, force=True
                )
            with self.assertRaises(sync.SyncError):
                sync.copy_file(source, destination_link, dry_run=False, force=True)

    def test_safe_join_rejects_symlink_component(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / "outside"
            outside.mkdir()
            link = root / "link"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks unavailable")

            with self.assertRaises(sync.SyncError):
                sync._safe_join(root, "link/file.txt")

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

    def test_force_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            destination = root / "destination.txt"
            source.write_text("new", encoding="utf-8")
            destination.write_text("old", encoding="utf-8")

            sync.copy_file(source, destination, dry_run=False, force=True)

            self.assertEqual(destination.read_text(encoding="utf-8"), "new")
            self.assertEqual(list(root.glob(".destination.txt.*")), [])

    def test_failed_publication_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            destination = root / "destination.txt"
            source.write_text("safe", encoding="utf-8")
            with (
                mock.patch.object(
                    sync.os, "replace", side_effect=OSError("publish failed")
                ),
                self.assertRaises(OSError),
            ):
                sync.copy_file(source, destination, dry_run=False, force=True)
            self.assertEqual(list(root.glob(".destination.txt.*")), [])

    def test_cli_rejects_invalid_command(self):
        with self.assertRaises(SystemExit) as raised:
            sync.main(["invalid"])
        self.assertEqual(raised.exception.code, 2)

    def test_install_optional_and_required_mappings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            optional = sync.Mapping("test", "optional.txt", "home", "optional.txt")
            required = sync.Mapping(
                "test", "required.txt", "home", "required.txt", True
            )

            self.assertEqual(
                sync.install_files((optional,), repo, platform="darwin", home=home), 0
            )
            with self.assertRaises(sync.SyncError):
                sync.install_files((required,), repo, platform="darwin", home=home)

    def test_optional_and_required_mappings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            optional = sync.Mapping("test", "optional.txt", "home", "optional.txt")
            required = sync.Mapping(
                "test", "required.txt", "home", "required.txt", True
            )

            self.assertEqual(
                sync.export_files((optional,), repo, platform="darwin", home=home), 0
            )
            with self.assertRaises(sync.SyncError):
                sync.export_files((required,), repo, platform="darwin", home=home)

    def test_export_install_check_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            source = home / ".pi" / "AGENTS.md"
            source.parent.mkdir()
            source.write_text("theme = 'dark'\\n", encoding="utf-8")
            manifest = (
                sync.Mapping("pi", "configs/pi/AGENTS.md", "home", ".pi/AGENTS.md"),
            )

            self.assertEqual(
                sync.export_files(manifest, repo, platform="darwin", home=home), 1
            )
            source.write_text("theme = 'light'\\n", encoding="utf-8")
            self.assertEqual(
                sync.install_files(
                    manifest, repo, platform="darwin", home=home, force=True
                ),
                1,
            )
            self.assertEqual(source.read_text(encoding="utf-8"), "theme = 'dark'\\n")
            self.assertEqual(
                sync.check_files(manifest, repo, platform="darwin", home=home), 0
            )

    def test_check_files_rejects_hardlinks(self):
        if not hasattr(os, "link"):
            self.skipTest("hardlinks unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            source = home / "source.txt"
            linked = home / "linked.txt"
            source.write_text("theme = 'dark'", encoding="utf-8")
            os.link(source, linked)
            manifest = (sync.Mapping("test", "linked.txt", "home", "linked.txt"),)
            self.assertEqual(
                sync.check_files(manifest, repo, platform="darwin", home=home), 1
            )

    def test_export_rejects_dangling_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            source = home / "dangling.txt"
            try:
                source.symlink_to(home / "missing.txt")
            except (NotImplementedError, OSError):
                self.skipTest("symlinks unavailable")
            manifest = (sync.Mapping("test", "safe.txt", "home", "dangling.txt"),)
            with self.assertRaises(sync.SyncError):
                sync.export_files(manifest, repo, platform="darwin", home=home)

    def test_install_rejects_dangling_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            source = repo / "safe.txt"
            source.symlink_to(repo / "missing.txt")
            manifest = (sync.Mapping("test", "safe.txt", "home", "safe.txt"),)
            with self.assertRaises(sync.SyncError):
                sync.install_files(manifest, repo, platform="darwin", home=home)

    def test_check_files_reports_dangling_symlink_as_unsafe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            source = home / "dangling.txt"
            try:
                source.symlink_to(home / "missing.txt")
            except (NotImplementedError, OSError):
                self.skipTest("symlinks unavailable")
            manifest = (sync.Mapping("test", "safe.txt", "home", "dangling.txt"),)
            self.assertEqual(
                sync.check_files(manifest, repo, platform="darwin", home=home), 1
            )

    def test_check_files_reports_required_missing_and_safe_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            (repo / "safe.txt").write_text("theme = 'dark'", encoding="utf-8")
            (home / "safe.txt").write_text("theme = 'dark'", encoding="utf-8")
            manifest = (
                sync.Mapping("test", "safe.txt", "home", "safe.txt"),
                sync.Mapping("test", "missing.txt", "home", "missing.txt", True),
            )

            self.assertEqual(
                sync.check_files(manifest, repo, platform="darwin", home=home), 2
            )

    def test_repository_root_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            actual = root / "repo"
            actual.mkdir()
            link = root / "repo-link"
            try:
                link.symlink_to(actual, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks unavailable")

            with self.assertRaises(sync.SyncError):
                sync.check_files((), link, platform="darwin", home=root / "home")


if __name__ == "__main__":
    unittest.main()
