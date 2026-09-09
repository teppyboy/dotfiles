# AGENTS.md

## Rules

- Keep the sync manifest explicit and allowlist-only.
- Never commit API keys, tokens, passwords, cookies, private keys, auth state, history, logs, caches, databases, or machine-specific secrets.
- Review every new config file manually before adding it to `scripts/sync.py`.
- Prefer Python standard library and the smallest safe diff.
- Do not broaden directory copies or weaken secret screening.
- Keep JSON/JSONC sanitization key/path rules explicit and manually reviewed.
- Never sync `auth.json`, runtime state, package locks, `node_modules`, or installed package source.
- Use explicit directory roots only; never sync a broad parent directory.

## Checks

```text
python -m unittest discover -s tests -v
python -m py_compile scripts/sync.py tests/test_sync.py
git diff --check
```
