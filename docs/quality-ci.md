# Multi-Repository Code Quality (Qlty CLI)

Zero-cost, locally executed static analysis and maintainability governance using **Qlty CLI** and **GitHub Actions** — with no Qlty Cloud account, paid SaaS, paid AI APIs, or continuously running server.

## Architecture

| Component | Location | Responsibility |
|---|---|---|
| Shared policy source | `source.toml` (root of `joaovpimenta/joaovpimenta`) | Shared `exclude_patterns`, `test_patterns`, and built-in code smell thresholds; consumed via pinned Git tags (`qlty-vX.Y.Z`) |
| Reusable CI workflow | `.github/workflows/quality.yml` | Read-only `workflow_call` runner with pinned action SHAs, Sigstore-verified pinned Qlty CLI, dynamic PR base ref, and sanitized artifacts |
| Gate evaluator | `scripts/quality-gate.mjs` + `scripts/quality-gate.test.mjs` | Fail-closed SARIF/metrics evaluator, secret/snippet redaction, and GitHub Job Summary generator |
| Reference caller | `governance/defaults/quality-caller.yml` | Opt-in thin caller template for participating repos |
| Target repository | `.qlty/qlty.toml` + `.github/workflows/quality.yml` | Declares shared source tag, language-specific plugins, and repo overrides |

## Zero-cost & licensing posture

- **Cost:** R$ 0. No Qlty Cloud (`coverage publish`, `coverage complete`, `dashboard`), no `slop-one` AI calls, no paid GitHub Advanced Security, and no paid Gitleaks Action.
- **Telemetry:** Disabled everywhere via `QLTY_TELEMETRY=off` and `--no-upgrade-check`.
- **Qlty CLI license:** BSL 1.1 (Fair Source) — free for personal, open-source, and internal commercial use; transitions to GPLv3 on December 10, 2028. Versions are explicitly pinned (`0.672.0`) and verified with both SHA-256 and `gh attestation verify --repo qltysh/qlty`.
- **Analyzers:** Open-source CLIs (ESLint, actionlint, Gitleaks CLI, OSV-Scanner, Ruff, Checkstyle, PMD, ShellCheck, Trivy, etc.).

## Configuration layering and merging

1. Built-in Qlty `default` source supplies analyzer definitions.
2. `personal-quality-policy` (`https://github.com/joaovpimenta/joaovpimenta.git`, pinned `tag = "qlty-v0.2.0"`) provides shared exclusions, test patterns, and maintainability smell thresholds.
3. Project `.qlty/qlty.toml` enables only the analyzers relevant to that repository and overrides any threshold or exclusion as needed.
4. **Per-project GitHub Actions Variables (`vars.QLTY_*`)** govern the CI pipeline behavior for each repository (no silent defaults for required settings). Optional `workflow_dispatch` inputs (`scope_override`, `enforcement_override`) may override scope/enforcement for ad-hoc audits.

Inspect the effective merged configuration in any repository with:

```bash
QLTY_TELEMETRY=off qlty config validate --no-upgrade-check
QLTY_TELEMETRY=off qlty config show --no-upgrade-check
```

## Per-project environment variables (`vars.QLTY_*`)

The reusable workflow reads `${{ vars.QLTY_* }}` directly from the **caller repository** (`Settings -> Secrets and variables -> Actions -> Variables`).

**Fail-closed rule:** if any required variable is missing or invalid (or `.qlty/qlty.toml` is absent), the pipeline fails immediately at step 1 with an explicit `::error::` annotation and Job Summary stating that **a esteira precisa ser corrigida** before running.

### Required variables

| Variable | Accepted values | Example |
|---|---|---|
| `QLTY_SCOPE` | `pr` or `full` | `pr` |
| `QLTY_ENFORCEMENT` | `report-only`, `standard`, or `strict` | `standard` |
| `QLTY_VERSION` | Pinned SemVer without leading `v` | `0.672.0` |
| `QLTY_POLICY_REF` | Pinned tag or SHA in `joaovpimenta/joaovpimenta` | `qlty-v0.2.0` |
| `QLTY_ENABLE_SMELLS` | `true` or `false` | `true` |
| `QLTY_ENABLE_METRICS` | `true` or `false` | `true` |

### Optional variables

| Variable | Default | Accepted values |
|---|---|---|
| `QLTY_ADVISORY_PLUGINS` | _(empty)_ | Comma-separated plugin names kept advisory (e.g. `osv-scanner`) |
| `QLTY_BLOCK_SMELLS` | `false` | `true` or `false` (promotes smells to blocking in `standard` mode) |
| `QLTY_ARTIFACT_RETENTION_DAYS` | `7` | Integer `1..90` |

Example bootstrap via GitHub CLI:

```bash
gh variable set QLTY_SCOPE --repo OWNER/REPO --body "pr"
gh variable set QLTY_ENFORCEMENT --repo OWNER/REPO --body "standard"
gh variable set QLTY_VERSION --repo OWNER/REPO --body "0.672.0"
gh variable set QLTY_POLICY_REF --repo OWNER/REPO --body "qlty-v0.2.0"
gh variable set QLTY_ENABLE_SMELLS --repo OWNER/REPO --body "true"
gh variable set QLTY_ENABLE_METRICS --repo OWNER/REPO --body "true"
```

## Gate policy contract

| Mode | Tool/Config Errors | Exposed Secrets | Blocking Analyzer `error` | Maintainability Smells | `advisory_plugins` |
|---|---|---|---|---|---|
| `report-only` | **FAIL (closed)** | Advisory | Advisory | Advisory | Advisory |
| `standard` (default) | **FAIL (closed)** | **FAIL** | **FAIL** | Advisory (unless `block_smells: true`) | Advisory |
| `strict` | **FAIL (closed)** | **FAIL** | **FAIL** (and `warning`) | **FAIL** | Advisory |

- Existing native checks (`pnpm lint`, `tsc --noEmit`, `vitest`, Maven/Gradle, Playwright) remain authoritative and are never replaced by Qlty.
- Cyclomatic complexity (max 10 paths/function) is enforced via native language linters (ESLint `complexity`, Checkstyle `CyclomaticComplexity`, Ruff `C901`), separate from Qlty's cognitive complexity smell (`function_complexity`, threshold 15).
- Secret findings are always redacted in Job Summaries, `gate-summary.json`, and uploaded SARIF artifacts.

## Managing plugins, thresholds, and suppressions

### Enabling or disabling a plugin per repository

Add or remove `[[plugin]]` entries with pinned versions in the repository's `.qlty/qlty.toml`:

```toml
[[plugin]]
name = "actionlint"
version = "1.7.9"
```

To skip a plugin on specific paths without blanket-excluding security checks:

```toml
[[exclude]]
plugins = ["eslint"]
patterns = ["generated/**"]
```

### Overriding smell thresholds

Override any shared threshold directly in `.qlty/qlty.toml`:

```toml
[smells.nested_control_flow]
threshold = 4
```

### Targeted suppressions (`[[triage]]` and `qlty-ignore`)

Document rationale and removal criteria for every suppression:

```toml
# Rationale: legacy parser scheduled for refactor in #123.
[[triage]]
match = { plugin = "osv-scanner", path = "pnpm-lock.yaml" }
set = { mode = "monitor" }
```

Inline source suppressions use narrow `qlty-ignore` comments with a short justification.

## Upgrading versions safely

1. Update `qlty_version` in `.github/workflows/quality.yml` and `.github/workflows/quality-self-check.yml` after reviewing `qltysh/qlty` release notes and `LICENSE.md`.
2. Update `source.toml` if changing shared thresholds/exclusions.
3. Run `node --test scripts/quality-gate.test.mjs` and verify `quality-self-check.yml` passes.
4. Create a new annotated tag (e.g., `qlty-v0.2.0`) and test it on the pilot repo (`joaovpimenta/are`) before bumping callers in other repos.

## Rollback

- **Per-repository:** revert the caller PR or switch `enforcement: report-only` (or pin back to the previous `qlty-vX.Y.Z` tag).
- **Control plane:** keep old `qlty-vX.Y.Z` tags immutable; callers pinned to a previous tag are unaffected by newer commits on `main`.

## Pilot baseline (`joaovpimenta/are`, 2026-11-22)

- **Existing checks preserved:** `lint` (ESLint 10 flat config), `typecheck` (`tsc --noEmit`), `unit-tests` (Vitest 5), `build`, `bundle-size`, `interaction-tests`, `smoke-tests` (Playwright), `ci-gate`, `validated-site` → `pages.yml`.
- **Newly added via Qlty:** `actionlint` (0 findings across 4 workflows), `gitleaks` (offline secret scanning), `osv-scanner` (13 pre-existing lockfile advisories reported as advisory during baseline), built-in smells (53 existing baseline findings across 85 source files with `tests/**` classified as tests: 26 `function-complexity`, 7 `nested-control-flow`, 6 `similar-code`, 5 `return-statements`, 4 `file-complexity`, 2 `boolean-logic`, 2 `identical-code`, 1 `function-parameters`), and complexity metrics (`SequenceInput` cognitive 22 / cyclo 13; `LabHarness` cognitive 19 / cyclo 18).
- **Pilot PR policy:** `scope: pr`, `enforcement: standard`, `advisory_plugins: osv-scanner`, `block_smells: false` — blocks new workflow syntax errors and exposed secrets while reporting smells and existing dependency debt without breaking deploys.

## Rollout waves (opt-in, approval required per wave)

1. **Wave 0 (Pilot):** `joaovpimenta/are` (TypeScript/React/Three.js monorepo).
2. **Wave 1 (Cross-stack validation):** 1 Java/Maven repo (e.g. `busca-cnpj-cli`) + 1 mixed JS/Python repo (e.g. `tech-topics` or `azure-ai-200`).
3. **Wave 2 (Active personal repos):** Small batches by stack; forks remain report-only until maintenance intent is confirmed; archived/non-code repos opt out.
