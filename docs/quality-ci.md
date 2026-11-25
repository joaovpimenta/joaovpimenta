# Multi-Repository Code Quality & Stack Gates (Qlty CLI)

Zero-cost, locally executed static analysis, cyclomatic complexity, test execution, and coverage governance using **Qlty CLI** and **GitHub Actions** — with no Qlty Cloud account, paid SaaS, paid AI APIs, or continuously running server.

## Architecture

| Component | Location | Responsibility |
|---|---|---|
| Shared policy source | `source.toml` (root of `joaovpimenta/joaovpimenta`) | Shared `exclude_patterns`, `test_patterns`, and built-in code smell thresholds; consumed via pinned Git tags (`qlty-vX.Y.Z`) |
| Universal quality gate | `.github/workflows/quality.yml` | Core `workflow_call` gate: validates `vars.QLTY_*` fail-closed, runs pinned Sigstore-verified Qlty CLI, evaluates static findings + smells + cyclomatic complexity + total/diff coverage + JUnit test counts |
| Stack reusable gates | `.github/workflows/quality-{web,java,android,python,shell}.yml` | Run native stack tests + export standardized `quality-test-reports` (LCOV / JaCoCo XML / Cobertura XML + JUnit XML), then chain `./.github/workflows/quality.yml` |
| Gate evaluator | `scripts/quality-gate.mjs` + `scripts/quality-gate.test.mjs` | Zero-dependency Node.js evaluator for SARIF, Qlty metrics, LCOV, JaCoCo XML, Cobertura XML, unified PR diffs, and JUnit XML |
| Ready-to-copy callers | `governance/defaults/quality-callers/*.yml` & `governance/defaults/quality-caller.yml` | Thin caller templates with full commented variable references and `gh variable set` snippets per stack |

## Stack Gates

| Stack | Reusable workflow | Native coverage formats | Caller template |
|---|---|---|---|
| **Web / Node / TS / JS** | `.github/workflows/quality-web.yml@qlty-v0.3.0` | LCOV (`lcov.info`), Cobertura XML + JUnit XML | `governance/defaults/quality-callers/web.yml` |
| **Java / Spring (Maven & Gradle)** | `.github/workflows/quality-java.yml@qlty-v0.3.0` | JaCoCo XML + Surefire/Gradle JUnit XML | `governance/defaults/quality-callers/java.yml` |
| **Android (Gradle JVM / Robolectric)** | `.github/workflows/quality-android.yml@qlty-v0.3.0` | JaCoCo XML / Kover XML + JUnit XML | `governance/defaults/quality-callers/android.yml` |
| **Python (pytest)** | `.github/workflows/quality-python.yml@qlty-v0.3.0` | Cobertura XML + JUnit XML | `governance/defaults/quality-callers/python.yml` |
| **Shell / Static / Docs** | `.github/workflows/quality-shell.yml@qlty-v0.3.0` | Optional Bats/kcov or `QLTY_COVERAGE_MODE=none` | `governance/defaults/quality-callers/shell-static.yml` |
| **Universal (bring your own test job)** | `.github/workflows/quality.yml@qlty-v0.3.0` | Downloads `quality-test-reports` artifact | `governance/defaults/quality-caller.yml` |

> **Android note:** `quality-android.yml` runs JVM unit tests (`testDebugUnitTest`) and Robolectric on free `ubuntu-latest` runners. Emulator-based instrumented tests (`connectedAndroidTest`) lack consistent KVM acceleration on standard free runners and should stay in a separate workflow when needed.

## Zero-cost & licensing posture

- **Cost:** R$ 0. No Qlty Cloud (`coverage publish`, `coverage complete`, `dashboard`), no `slop-one` AI calls, no paid GitHub Advanced Security, and no paid Gitleaks Action.
- **Telemetry:** Disabled everywhere via `QLTY_TELEMETRY=off` and `--no-upgrade-check`.
- **Qlty CLI license:** BSL 1.1 (Fair Source) — free for personal, open-source, and internal commercial use; transitions to GPLv3 on December 10, 2028. Versions are explicitly pinned (`0.672.0`) and verified with both SHA-256 and `gh attestation verify --repo qltysh/qlty`.
- **Analyzers:** Open-source CLIs (ESLint, actionlint, Gitleaks CLI, OSV-Scanner, Ruff, Checkstyle, PMD, ShellCheck, Trivy, etc.).

## Per-project environment variables (`vars.QLTY_*`)

All reusable workflows read `${{ vars.QLTY_* }}` directly from the **caller repository** (`Settings -> Secrets and variables -> Actions -> Variables`).

**Fail-closed rule:** if any required variable is missing or invalid, `.qlty/qlty.toml` is absent, or `QLTY_COVERAGE_MODE=required` has no coverage/JUnit report, the pipeline fails immediately with an explicit `::error::` annotation and Job Summary stating **"A esteira precisa ser corrigida"**.

### Core variables (required in every repository)

| Variable | Accepted values | Target default |
|---|---|---|
| `QLTY_SCOPE` | `pr` or `full` | `pr` |
| `QLTY_ENFORCEMENT` | `report-only`, `standard`, or `strict` | `standard` |
| `QLTY_VERSION` | Pinned SemVer without leading `v` | `0.672.0` |
| `QLTY_POLICY_REF` | Pinned tag or SHA in `joaovpimenta/joaovpimenta` | `qlty-v0.3.0` |
| `QLTY_ENABLE_SMELLS` | `true` or `false` | `true` |
| `QLTY_ENABLE_METRICS` | `true` or `false` | `true` |
| `QLTY_MAX_CYCLOMATIC` | Integer `1..100` or `off` (requires `QLTY_ENABLE_METRICS=true` when numeric) | `10` |
| `QLTY_COVERAGE_MODE` | `required` or `none` | `required` (`none` for docs/static) |

### Coverage & test variables (required when `QLTY_COVERAGE_MODE=required`)

| Variable | Accepted values | Target default |
|---|---|---|
| `QLTY_MIN_COVERAGE_TOTAL` | Number `0..100` (%) — customizable per repo (e.g. lower baseline on legacy repos) | `90` |
| `QLTY_MIN_COVERAGE_DIFF` | Number `0..100` (%) — coverage required on new/modified executable lines in PR | `90` |
| `QLTY_MIN_TESTS` | Integer `>= 1` — minimum executed tests reported in JUnit XML | `1` |

### Optional core variables

| Variable | Default | Accepted values |
|---|---|---|
| `QLTY_ADVISORY_PLUGINS` | _(empty)_ | Comma-separated plugin names kept advisory (e.g. `osv-scanner`) |
| `QLTY_BLOCK_SMELLS` | `false` | `true` or `false` (promotes maintainability smells to blocking in `standard` mode) |
| `QLTY_ALLOW_SKIPPED_TESTS` | `true` | `true` or `false` (`false` blocks skipped tests in JUnit XML) |
| `QLTY_COVERAGE_DIFF_FAIL_ON_EMPTY` | `false` | `true` or `false` (`true` fails PRs with 0 executable diff lines) |
| `QLTY_ARTIFACT_RETENTION_DAYS` | `7` | Integer `1..90` |

### Stack-specific variables

- **Web (`quality-web.yml`):**
  - Required: `QLTY_WEB_NODE_VERSION`, `QLTY_WEB_PACKAGE_MANAGER` (`pnpm`\|`npm`\|`yarn`\|`none`), `QLTY_WEB_TEST_CMD` (when `QLTY_COVERAGE_MODE=required`).
  - Optional: `QLTY_WEB_PNPM_VERSION`, `QLTY_WEB_INSTALL_CMD`, `QLTY_WEB_LINT_CMD`, `QLTY_WEB_TYPECHECK_CMD`, `QLTY_WEB_BUILD_CMD`, `QLTY_WEB_E2E_CMD`, `QLTY_WEB_COVERAGE_DIR` (`coverage`), `QLTY_WEB_WORKDIR` (`.`).
- **Java (`quality-java.yml`):**
  - Required: `QLTY_JAVA_VERSION`, `QLTY_JAVA_BUILD_TOOL` (`maven`\|`gradle`).
  - Optional: `QLTY_JAVA_DISTRIBUTION` (`temurin`), `QLTY_JAVA_TEST_CMD`, `QLTY_JAVA_WORKDIR` (`.`).
- **Android (`quality-android.yml`):**
  - Required: `QLTY_ANDROID_JAVA_VERSION`.
  - Optional: `QLTY_ANDROID_TEST_TASK` (`testDebugUnitTest`), `QLTY_ANDROID_COVERAGE_TASK` (`jacocoTestReport` or `koverXmlReport`), `QLTY_ANDROID_LINT_TASK`, `QLTY_ANDROID_TEST_CMD`, `QLTY_ANDROID_WORKDIR` (`.`).
- **Python (`quality-python.yml`):**
  - Required: `QLTY_PYTHON_VERSION`.
  - Optional: `QLTY_PYTHON_INSTALL_CMD`, `QLTY_PYTHON_TEST_CMD`, `QLTY_PYTHON_WORKDIR` (`.`).
- **Shell / Static (`quality-shell.yml`):**
  - Optional: `QLTY_SHELL_TEST_CMD`, `QLTY_SHELL_WORKDIR` (`.`).

## Gate policy contract

| Mode | Tool/Config Errors | Exposed Secrets | Blocking Analyzer `error` | Cyclomatic / Coverage / Min Tests | Maintainability Smells | `advisory_plugins` |
|---|---|---|---|---|---|---|
| `report-only` | **FAIL (closed)** | Advisory | Advisory | Advisory | Advisory | Advisory |
| `standard` | **FAIL (closed)** | **FAIL** | **FAIL** | **FAIL** | Advisory (unless `QLTY_BLOCK_SMELLS=true`) | Advisory |
| `strict` | **FAIL (closed)** | **FAIL** | **FAIL** (and `warning`) | **FAIL** | **FAIL** | Advisory |

- Secret findings are always redacted in Job Summaries, `gate-summary.json`, and uploaded SARIF artifacts.
- Old immutable tags (`qlty-v0.1.0`, `qlty-v0.2.0`) remain untouched so existing callers never break unexpectedly when `qlty-v0.3.0` is released.

## Upgrading & validating locally

```bash
node --test scripts/quality-gate.test.mjs
QLTY_TELEMETRY=off qlty config validate --no-upgrade-check
```
