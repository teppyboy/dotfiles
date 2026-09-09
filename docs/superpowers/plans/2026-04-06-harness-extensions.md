# Harness Extensions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the public dotfiles repository with Pi MCP/model settings, sanitized OpenCode configs, and explicit safe plugin/skill directories.

**Architecture:** Keep one explicit manifest in `scripts/sync.py`. Add three entry modes: raw single-file copy, sanitized JSON/JSONC copy, and recursive copy under named directories. Sanitization preserves config shape while replacing API endpoints and credential values with environment placeholders. `auth.json`, caches, package source, dependencies, and runtime state remain outside the manifest.

**Tech Stack:** Python 3.10+ standard library: `argparse`, `json`, `os`, `pathlib`, `re`, `shutil`, `tempfile`, `unittest`.

---

## File Map

- Modify: `scripts/sync.py` — manifest modes, JSONC parsing, sanitization, recursive roots, export/install/check integration.
- Modify: `tests/test_sync.py` — sanitizer, manifest, recursive-root, exclusion, and source-immutability tests.
- Modify: `README.md` — supported files, placeholders, exclusions, and setup.
- Modify: `AGENTS.md` — sanitizer and recursive-root maintenance rules.
- Create: `configs/pi/settings.json` — approved verbatim Pi settings.
- Create: `configs/pi/mcp.json` — public Pi MCP configuration.
- Create: `configs/pi/models.json` — sanitized Pi model-provider configuration.
- Create: `configs/opencode/opencode.json` — sanitized OpenCode configuration.
- Create: `configs/opencode/opencode-openai-compatible.json` — sanitized OpenAI-compatible configuration.
- Create: `configs/opencode/dcp.jsonc` — public DCP configuration.
- Create: safe files under `configs/opencode/plugins/`, `skills/`, `agents/`, `commands/`, and `tools/`.

Never create or track `auth.json`, `mcp-cache.json`, `run-history.jsonl`, `.ocx/`, `node_modules/`, package locks, caches, sessions, tasks, or installed `pi-mcp-adapter` package source.

### Task 1: Add failing tests for manifest modes and sanitization

**Files:**

- Modify: `tests/test_sync.py`

- [ ] **Step 1: Extend the test module imports and helpers**

Keep the existing dynamic import of `scripts/sync.py`, `unittest.TestCase`, and temporary-directory style. Add only standard-library imports required by the new tests: `json`, `os`, and `base64` if encoded fixtures are useful.

- [ ] **Step 2: Test sanitized JSON without source mutation**

Add a test equivalent to:

```python
def test_sanitized_json_replaces_endpoint_and_secret(self):
    source = '{"baseURL":"https://private.example/v1","apiKey":"live-value"}'
    sanitized = sync.sanitize_config(source, "opencode")
    self.assertEqual(json.loads(sanitized), {
        "baseURL": "${OPENCODE_API_BASE_URL}",
        "apiKey": "${OPENCODE_API_KEY}",
    })
    self.assertEqual(
        source,
        '{"baseURL":"https://private.example/v1","apiKey":"live-value"}',
    )
```

- [ ] **Step 3: Test JSONC parsing and nested sanitization**

Use comments, trailing commas, nested provider objects, arrays, `headers`, `hostname`, `baseURL`, `apiKey`, `token`, and `clientSecret`. Assert comments disappear in output, endpoint fields become the app-specific endpoint placeholder, credential fields become the app-specific key placeholder, unrelated public settings remain unchanged, and output is valid JSON.

- [ ] **Step 4: Test fail-closed unknown credential fields**

Pass a config containing an unknown key whose name clearly indicates a credential, such as `mysterySecret`, and assert `SyncError`. Pass a config containing a real-looking credential value in an otherwise public field and assert `SyncError` after sanitization.

- [ ] **Step 5: Test recursive roots and exclusions**

Create temporary `opencode/plugins/` and sibling files. Put one safe file under `plugins/`, plus `auth.json`, `node_modules/x.js`, `package-lock.json`, and a symlink when supported. Run the directory-mode helper with only `plugins` in its manifest. Assert the safe file is copied, excluded files are not copied, symlinks are rejected/skipped safely, and sibling files remain absent.

- [ ] **Step 6: Test all new mapping paths**

Construct a temporary home root with:

```text
.pi/agent/settings.json
.pi/agent/mcp.json
.pi/agent/models.json
.config/opencode/opencode.json
.config/opencode/opencode-openai-compatible.json
.config/opencode/dcp.jsonc
.config/opencode/plugins/example.ts
.config/opencode/skills/example/SKILL.md
.config/opencode/agents/example.md
.config/opencode/commands/example.md
.config/opencode/tools/example.md
.config/opencode/auth.json
.config/opencode/node_modules/example.js
```

Use an injected manifest and roots. Assert new safe files map to the matching repository paths; `auth.json` and `node_modules` do not.

- [ ] **Step 7: Test Pi settings and OpenCode source immutability**

Export with temporary roots. Assert `settings.json` is copied verbatim. Assert sanitized JSON outputs contain placeholders, not original hostnames or credential values. Assert every source file remains byte-for-byte unchanged.

- [ ] **Step 8: Run tests to confirm the new tests fail**

Run: `python -m unittest discover -s tests -v`

Expected: existing tests pass; new tests fail because the new modes and manifest entries do not yet exist.

- [ ] **Step 9: Commit tests**

```bash
git add tests/test_sync.py
git commit -m "test: define extended harness sync behavior"
```

### Task 2: Implement JSON/JSONC sanitization and manifest modes

**Files:**

- Modify: `scripts/sync.py`

- [ ] **Step 1: Extend `Mapping` and validate modes**

Add `mode: str = "file"` to `Mapping`. Accept exactly `file`, `sanitized_json`, `sanitized_jsonc`, and `directory`. Reject unknown modes, absolute paths, traversal, sensitive manifest paths, and duplicate repository paths.

- [ ] **Step 2: Implement string-aware JSONC comment removal**

Write a small scanner that tracks quoted strings and escapes. Remove `//` comments outside strings and `/* ... */` comments outside strings. Remove trailing commas only outside strings before `}` or `]`. Parse the result with `json.loads`; convert decode errors to `SyncError`. Do not use a regex that can modify URLs or quoted text.

- [ ] **Step 3: Implement recursive sanitization**

Use app-specific placeholders:

```python
PLACEHOLDERS = {
    "pi": {
        "endpoint": "${PI_API_BASE_URL}",
        "secret": "${PI_PROVIDER_API_KEY}",
    },
    "opencode": {
        "endpoint": "${OPENCODE_API_BASE_URL}",
        "secret": "${OPENCODE_API_KEY}",
    },
}
```

Sanitize recursively by key and path. Endpoint fields include `baseURL`, `baseUrl`, `base_url`, `endpoint`, `hostname`, and API-server `url`. Secret fields include `apiKey`, `api_key`, `token`, `accessToken`, `refreshToken`, `clientSecret`, `password`, `secret`, `authorization`, `bearerToken`, and `headers` values that are credentials. Preserve booleans, numbers, arrays, public plugin names, public MCP server names, and non-server URLs.

Reject unknown credential-like key names and credential-like values that remain after replacement. Run the existing bounded scanner on sanitized output. Never log source values. Return deterministic JSON with `json.dumps(..., indent=2, ensure_ascii=False) + "\n"`.

- [ ] **Step 4: Add mode-specific file processing**

`file` reads and validates bytes. `sanitized_json` parses JSON and sanitizes it. `sanitized_jsonc` parses JSONC and sanitizes it. All modes use existing bounded reads, path/link/hardlink checks, and atomic publication. Export writes sanitized output only to the repository; install writes the already-sanitized repository output without reading live secrets.

- [ ] **Step 5: Run focused tests**

Run: `python -m unittest discover -s tests -v`

Expected: sanitization and mode tests pass; recursive directory and full manifest tests may still fail until Task 3.

- [ ] **Step 6: Commit sanitizer implementation**

```bash
git add scripts/sync.py tests/test_sync.py
git commit -m "feat: sanitize harness configuration exports"
```

### Task 3: Implement explicit recursive roots and add the complete manifest

**Files:**

- Modify: `scripts/sync.py`
- Modify: `tests/test_sync.py`

- [ ] **Step 1: Add explicit exclusions and budgets**

Use these exclusions at minimum:

```python
EXCLUDED_DIRECTORY_NAMES = {".git", ".ocx", "node_modules", "__pycache__"}
EXCLUDED_FILE_NAMES = {
    "auth.json",
    "mcp-cache.json",
    "package-lock.json",
    "run-history.jsonl",
}
```

Also apply existing sensitive-name, sensitive-extension, symlink, hardlink, regular-file, bounded-read, and credential-content checks. Add a finite maximum file count and cumulative byte budget; exceed either with `SyncError`.

- [ ] **Step 2: Walk only named directory roots**

For `directory` mappings, walk only the source directory represented by `relative_path`. Do not discover sibling roots. Do not follow symlinks. Preserve the path relative to the named root under the matching repository directory. Skip excluded directories/files deterministically; reject unsafe content and unsafe links. Implement matching install and check behavior without deleting files.

- [ ] **Step 3: Replace the two-entry manifest with explicit safe mappings**

Use these entries, all optional unless the existing file is intentionally required:

```python
Mapping("pi", "configs/pi/AGENTS.md", "home", ".pi/AGENTS.md", mode="file"),
Mapping("pi", "configs/pi/settings.json", "home", ".pi/agent/settings.json", mode="file"),
Mapping("pi", "configs/pi/mcp.json", "home", ".pi/agent/mcp.json", mode="file"),
Mapping("pi", "configs/pi/models.json", "home", ".pi/agent/models.json", mode="sanitized_json"),
Mapping("opencode", "configs/opencode/AGENTS.md", "home", ".config/opencode/AGENTS.md", mode="file"),
Mapping("opencode", "configs/opencode/opencode.json", "home", ".config/opencode/opencode.json", mode="sanitized_json"),
Mapping("opencode", "configs/opencode/opencode-openai-compatible.json", "home", ".config/opencode/opencode-openai-compatible.json", mode="sanitized_json"),
Mapping("opencode", "configs/opencode/dcp.jsonc", "home", ".config/opencode/dcp.jsonc", mode="file"),
Mapping("opencode", "configs/opencode/plugins", "home", ".config/opencode/plugins", mode="directory"),
Mapping("opencode", "configs/opencode/skills", "home", ".config/opencode/skills", mode="directory"),
Mapping("opencode", "configs/opencode/agents", "home", ".config/opencode/agents", mode="directory"),
Mapping("opencode", "configs/opencode/commands", "home", ".config/opencode/commands", mode="directory"),
Mapping("opencode", "configs/opencode/tools", "home", ".config/opencode/tools", mode="directory"),
```

Do not add `auth.json`, package source, `node_modules`, caches, or generated/runtime paths. `pi-mcp-adapter` is represented by its existing package entry in `settings.json`, not by copying its installed directory.

- [ ] **Step 4: Integrate directory mode into export/install/check**

`export` copies raw files, sanitizes JSON/JSONC files, and recursively copies safe files under named roots. `install` restores repository files; it never restores excluded paths. `check` validates manifest paths, source/repository presence, exclusions, and file safety without modifying either side. Preserve `--dry-run`, `--force`, optional-file handling, and no-deletion behavior.

- [ ] **Step 5: Run full tests**

Run: `python -m unittest discover -s tests -v`

Expected: all tests pass.

- [ ] **Step 6: Commit recursive sync and manifest**

```bash
git add scripts/sync.py tests/test_sync.py
git commit -m "feat: sync explicit harness directories"
```

### Task 4: Export safe files and update documentation

**Files:**

- Create/update files under `configs/pi/` and `configs/opencode/` listed in the File Map.
- Modify: `README.md`
- Modify: `AGENTS.md`

- [ ] **Step 1: Preview and export**

Run:

```text
python scripts/sync.py export --dry-run
python scripts/sync.py export
```

Review only paths, sizes, and sanitized diffs. Confirm no source API keys, source hostnames, `auth.json`, caches, package locks, or `node_modules` enter `configs/`.

- [ ] **Step 2: Update README**

Document:

- Pi `settings.json`, `mcp.json`, and sanitized `models.json`.
- `pi-mcp-adapter` remains installed through the package declaration; its package source is not copied.
- OpenCode `opencode.json`, sanitized `opencode-openai-compatible.json`, `dcp.jsonc`, and explicit `plugins/`, `skills/`, `agents/`, `commands/`, and `tools/` roots.
- Placeholders `${PI_API_BASE_URL}`, `${PI_PROVIDER_API_KEY}`, `${OPENCODE_API_BASE_URL}`, and `${OPENCODE_API_KEY}`.
- Never-sync files and directories.
- Local environment setup is required after install.
- Manual diff review before commit.

- [ ] **Step 3: Update AGENTS.md**

Add rules requiring explicit manifest entries, manual review of sanitizer rules, no auth/runtime/package source files, no broad parent-directory sync, no weakening of safety checks, and full verification before merge.

- [ ] **Step 4: Run repository safety checks**

Run:

```bash
python -m unittest discover -s tests -v
python -m py_compile scripts/sync.py tests/test_sync.py
git diff --check
git ls-files | grep -E '(^|/)(auth\.json|mcp-cache\.json|package-lock\.json|node_modules/)' && exit 1 || true
```

Expected: tests pass; compilation succeeds; no whitespace errors; forbidden files are absent.

- [ ] **Step 5: Commit configs and documentation**

```bash
git add configs README.md AGENTS.md scripts/sync.py tests/test_sync.py
git commit -m "feat: add public-safe Pi and OpenCode harness configs"
```

### Task 5: Final review and verification

**Files:**

- Review all changed files.

- [ ] **Step 1: Review changed paths and sanitized content**

Run:

```bash
git diff master...HEAD --stat
git diff master...HEAD --name-only
python scripts/sync.py check
```

Manually inspect sanitized JSON values and confirm original API hostnames, API keys, authorization values, and auth state are absent. Confirm `settings.json` contains only the user-approved verbatim content.

- [ ] **Step 2: Run final commands from the repository root**

```bash
python -m unittest discover -s tests -v
python -m py_compile scripts/sync.py tests/test_sync.py
python scripts/sync.py check
python scripts/sync.py export --dry-run
python scripts/sync.py install --dry-run
git diff --check
git status --short --branch
```

Expected: all tests pass; compile and safety checks pass; dry runs create no files; working tree is clean after the final commit.

- [ ] **Step 3: Run a public-safety scan**

Scan tracked config files for actual credential-shaped values, private hostnames, auth files, and runtime state. Exclude detector regex literals and test fixtures from the result interpretation, but manually inspect every generated config. Any real value is a release blocker.

- [ ] **Step 4: Request final code review**

Review correctness, sanitization completeness, allowlist boundaries, cross-platform path handling, recursive-root exclusions, test coverage, and documentation. Resolve all Critical/Important findings before merge.
