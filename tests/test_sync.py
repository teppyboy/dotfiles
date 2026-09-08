from __future__ import annotations

import base64
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

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
            b'{"kty": "oct", "k": "symmetric-material"}',
            b'{"k": "symmetric-material", "kty": "OKP"}',
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

    def test_content_scanner_rejects_encoded_credentials(self):
        encoded = base64.b64encode(b"token=abc").decode()
        for content in (
            f"value={encoded}".encode(),
            base64.b64encode(b'{"token": "abc"}'),
            b"value=OPENAI%5FAPI%5FKEY%3Dabc",
            b"value=OPENAI\\x5fAPI\\x5fKEY=abc",
        ):
            with self.subTest(content=content), self.assertRaises(sync.SyncError):
                sync.ensure_safe_content(content)

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
        content = b" ".join(b"candidate%d" % index for index in range(sync.MAX_BASE64_CANDIDATES + 1))
        with self.assertRaises(sync.SyncError):
            sync.ensure_safe_content(content)

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
