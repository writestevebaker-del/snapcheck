---
name: snapcheck
description: >
  Run SnapCheck project health scans before git push, PR, or deploy. Use when
  the user asks to scan a project, check for secrets, run snapcheck, audit
  security, prepare for commit, review VPS/server health, or runs /snapcheck.
  Guides profile selection (git-repo/server/ci), interprets JSON reports, applies
  safe fixes, and blocks commits when critical findings exist.
metadata:
  short-description: "Scan projects for secrets and health issues"
---

# SnapCheck — Agent Workflow

SnapCheck is a zero-dependency CLI. **Always run it yourself** — never tell the user to run commands unless they ask.

Install if missing:

```bash
pip install -e .          # from repo root
# or: pipx install git+https://github.com/writestevebaker-del/snapcheck.git
```

## When to invoke

| Situation | Action |
|-----------|--------|
| Before `git push` / PR | `snapcheck scan . --profile git-repo --fail-on-critical` |
| After editing `.env`, configs, credentials | `snapcheck doctor .` |
| VPS / server paths (`/root`, `/var/www`, `/opt`) | `--profile server` |
| CI setup or pre-merge check | `--profile ci` |
| User says "is it safe to publish?" | full `doctor` + explain criticals |

## Profile selection

```
git-repo  → default for repositories (secrets in code, .env tracked)
server    → VPS: .ssh/ and letsencrypt/ are EXPECTED, not critical
ci        → fast: hide-noise + fail-on-critical, no duplicates/disk scan
```

System directory warning (`/`, `/home`, `/root` as scan root): prefer a project subpath or `--profile server`.

## Standard workflow

Copy this sequence for every pre-commit / pre-push audit:

```
1. snapcheck doctor <path>              # smart init + scan + recommendations
2. If critical_count > 0:
     snapcheck explain --finding "<KIND>"   # understand top finding
     snapcheck teach secrets               # if false positives dominate
     snapcheck fix <path>                  # safe .gitignore fixes only
     Re-scan until critical_count == 0 OR user explicitly accepts risk
3. snapcheck scan <path> --json           # structured output for agent
4. Gate: exit code 0 + critical == 0 before push/commit
```

## JSON report — fields agents must read

```bash
snapcheck scan . --json
```

| Field | Decision rule |
|-------|---------------|
| `health.critical` | **Must be 0** before push (unless user overrides) |
| `health.score` | Informational; score 85 with critical=1 is still blocked |
| `score_breakdown.lines` | Explain score drops to user |
| `recommendations[].commands` | Copy-paste fixes; execute safe ones after user confirm |
| `dangerous_files` | `.ovpn` in webroot, `id_rsa`, `.env` by path |
| `plugin_findings` | Custom plugin output |

Parse example (Python):

```python
import json, subprocess
out = subprocess.check_output(["snapcheck", "scan", ".", "--json"], text=True)
data = json.loads(out)
assert data["health"]["critical"] == 0, data["recommendations"]
```

## Decision rules (do not guess)

| Finding | Agent action |
|---------|----------------|
| `Config Password` in JSON/YAML | Critical — move to env, rotate password, never commit |
| `Private Key Block` in repo (git-repo) | Critical — `git rm --cached`, add to .gitignore |
| `Private Key Block` in `.ssh/` (server profile) | Expected — OK on VPS |
| `.ovpn` in `html/`, `www/`, `public/` | Critical — remove from webroot immediately |
| `api_key=ENV_VAR_NAME` (false positive) | Use `--hide-noise` or `.snapcheckignore` |
| Large log files | Warning — suggest rotation, not a security block |

## Commands reference

```bash
snapcheck scan . --profile git-repo --fail-on-critical
snapcheck scan /var/www --profile server --json
snapcheck scan . --profile ci                    # CI mode
snapcheck doctor .
snapcheck explain --finding "Config Password"
snapcheck teach ci                               # GitHub Actions YAML
snapcheck fix .                                  # interactive safe fixes
snapcheck fix . --yes                            # auto-apply safe .gitignore only
snapcheck baseline update .                      # accept known legacy findings
```

## Safe auto-fix vs needs confirmation

**Safe (fix --yes):** append lines to `.gitignore` / `.snapcheckignore`

**Needs user confirm:** `git rm --cached`, `rm` duplicates, key rotation, any deletion

**Never auto:** rotate API keys, delete files with real secrets

## Test fixtures (for self-verification)

From repo root:

```bash
pytest tests/test_agent_skill.py -v
.grok/skills/snapcheck/scripts/verify-workflow.sh
```

Expected outcomes:

| Fixture | Profile | critical | score |
|---------|---------|----------|-------|
| `tests/fixtures/clean/` | git-repo | 0 | ≥ 90 |
| `tests/fixtures/git-repo/` | git-repo | > 0 | < 70 |
| `tests/fixtures/json-secrets/` | git-repo | > 0 | — |
| `tests/fixtures/server-profile/` | server | 0 | ≥ 90 |
| `tests/fixtures/webroot/` | git-repo | > 0 | — |

## Reporting to user

Summarize in this format:

```
SnapCheck: {score}/100 · critical={n} · profile={profile}

Blockers (fix before push):
  - [path:line] kind — action from recommendations.commands

Info (optional):
  - score breakdown top deductions
```

If healthy: say so explicitly and suggest `snapcheck scan . --profile ci` for CI.