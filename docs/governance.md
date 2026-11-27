# Development HQ Governance

This repository is the control plane and source of truth for issue/project governance.

## Repository roles

### joaovpimenta/joaovpimenta

The controller repository owns:

- the canonical taxonomy in `governance/taxonomy.json`;
- global quality variable defaults in `governance/quality-defaults.json`;
- canonical Issue Form, pull request template, `AGENTS.md`, and thin workflow callers under `governance/defaults/`;
- the reusable workflows:
  - `.github/workflows/governance-event.yml` (Issue Form label enforcement);
  - `.github/workflows/dependabot-auto-merge.yml` (`dependabot[bot]` `minor`/`patch` auto-merge);
  - `.github/workflows/quality.yml` and stack gates (`quality-web.yml`, `quality-java.yml`, `quality-android.yml`, `quality-python.yml`, `quality-shell.yml`);
- the central repository reconciler (`scripts/governance-reconcile.mjs`) and pure policy engine (`scripts/governance-policy.mjs`, covered by unit tests in `scripts/governance-policy.test.mjs`);
- the Project metadata reconciler (`scripts/project-sync.mjs`);
- the scheduled sync and historical retrofit entry point (`.github/workflows/development-hq-sync.yml`).

No repository names are registered manually (this control plane is public). Repositories are discovered dynamically from the token.

### OWNER/.github

Each GitHub owner needs its own public repository named `.github` for account-level default community health files.

The controller also copies the canonical Issue Form, issue-template configuration, and pull request template directly into every governed repository. This is the enforcement path and means owner-level `.github` repositories are not required for governance to work.

If an owner-level `.github` repository exists, the controller mirrors the same defaults there as a native GitHub fallback for newly created repositories and other repositories not yet reconciled.

A personal `.github` repository only provides defaults for repositories owned by that personal account; an organization has its own owner scope. The controller intentionally does not auto-create owner repositories because they are optional and repository creation may require organization-level administrative permission.

## Canonical taxonomy

### Type

Exactly one:

- Epic
- Feature
- Bug
- Task
- Tech Debt
- Research

Type is represented by one managed `type:*` label and mirrored into the Project Type field.

### Area

One or more:

- Frontend
- Backend
- Design System
- Mobile
- Infra
- Docs
- Security

Areas are represented by managed `area:*` labels and mirrored into the Project Area multi-select field.

### Priority

Project field only:

- P0
- P1
- P2
- P3

Priority is intentionally manual. Automation never guesses priority.

### Status

- Inbox
- Ready
- In Progress
- Review
- Blocked
- Done

Automation only performs objective transitions:

- closed or merged work becomes Done;
- items without a status, or legacy Todo, become Inbox;
- legacy In progress becomes In Progress.

Ready, In Progress, Review, and Blocked otherwise remain human-controlled.

### Derived fields

- Organization = repository owner
- Product = repository
- Repository = GitHub native Project field

### Ambiguity

Unknown or inconsistent metadata receives `policy:needs-triage`. Automation does not guess ambiguous Type or Area.

## Governed repository scope & opt-in/opt-out topics

The governance writer intentionally uses a stricter scope than the Project reader.

A repository is governed when:

- it is not archived or disabled;
- the token has push access;
- it is owned by the personal Project owner, or it is organization-owned and the token reports admin access;
- it does **not** carry the topic `governance-ignore`; and
- it is **not a fork**, unless explicitly opted in with the topic `governance-managed`.

Topic controls (zero manual repo registry needed):

| Topic | Effect |
| --- | --- |
| `governance-ignore` | Opts the repository out of all governance writes. |
| `governance-managed` | Explicitly opts a forked repository into governance. |
| `qlty-enabled` | Opts a repository into Actions variable provisioning from `governance/quality-defaults.json` (also activated automatically when `.qlty/qlty.toml` exists). |
| `governance-ruleset-ignore` | Skips managed main-branch ruleset reconciliation on that repository. |

## Atomic PR sync & restricted Auto-Merge

Managed files are written as **one atomic commit** using the Git Data API rather than multiple individual commits:

- `GOVERNANCE_WRITE_MODE=pr` (**default**): creates/updates branch `chore/governance-sync` and opens or updates one pull request per repository.
- `GOVERNANCE_WRITE_MODE=direct`: pushes one atomic commit directly to the default branch.

Auto-merge for governance sync PRs is controlled by `GOVERNANCE_AUTO_MERGE`:

- `safe-only` (**default**): enables squash auto-merge **only** when **all** guardrails pass:
  1. Same repository (never from a fork).
  2. PR author is strictly the repository owner (`pr.user.login === owner`).
  3. Every commit on the PR is authored/committed by the repository owner (no external contributors).
  4. **Zero sensitive files** are touched (any change in `.github/workflows/*`, `.qlty/*`, `CODEOWNERS`, manifests/lockfiles such as `package.json`/`pom.xml`/`build.gradle`/`pyproject.toml`, `scripts/*`, or `.env*` blocks auto-merge and requires manual owner review).
- `off`: never enables auto-merge on governance PRs.

When auto-merge is enabled, GitHub only merges after all required status checks pass.

## Stack detection & Qlty variable provisioning

Without storing private repository names in this public repo, the reconciler inspects root manifest files (`package.json`, `pom.xml`, `build.gradle*`, `AndroidManifest.xml`, `pyproject.toml`, `requirements.txt`, etc.) to detect the stack (`web`, `java-maven`, `java-gradle`, `android`, `python`, `shell-static`).

For repositories with `.qlty/qlty.toml` or topic `qlty-enabled`, `governance/quality-defaults.json` drives Actions repository variables with two sync modes:

- `always-sync` (`QLTY_VERSION`, `QLTY_POLICY_REF`): kept aligned with the control plane.
- `create-if-missing` (`QUALITY_STACK`, `QLTY_GATE_MODE`, `QLTY_COVERAGE_MODE`, `QLTY_MIN_COVERAGE_TOTAL`, `QLTY_MIN_COVERAGE_DIFF`, `QLTY_MAX_CYCLOMATIC`, etc.): provisioned once and **never overwrites** repository-specific overrides.

## Free security hygiene & solo-friendly Rulesets

Applied automatically at zero cost (works on both public and private GitHub Free repositories):

- Repository merge hygiene: `delete_branch_on_merge: true`, `allow_auto_merge: true`, `allow_squash_merge: true`.
- Dependabot Vulnerability Alerts enabled (`PUT /vulnerability-alerts`).
- Dependabot Automated Security Fixes enabled (`PUT /automated-security-fixes`).

Applied opportunistically where the GitHub plan supports it (public repos; gracefully skipped without error on HTTP `403`/`422` for private repos on GitHub Free):

- Secret Scanning + Push Protection.
- Managed Ruleset `development-hq-main-protection` targeting `~DEFAULT_BRANCH`:
  - blocks branch deletion and non-fast-forward (force) pushes;
  - requires a Pull Request (`required_approving_review_count: 0`, solo-owner friendly);
  - requires status checks (`QLTY_REQUIRED_CHECKS` variable if defined, otherwise `qlty-quality` when `.qlty/qlty.toml` is present).

## Dependabot per stack (1 PR/week) & auto-merge

The reconciler manages `.github/dependabot.yml` (marked with `# managed-by: development-hq-governance`, never overwriting unmanaged custom files) with:

- `github-actions` + the detected package ecosystem (`npm`, `maven`, `gradle`, or `pip`);
- `schedule.interval: weekly` on `monday` and `open-pull-requests-limit: 1` (anti-spam);
- grouped `minor` and `patch` updates (never auto-grouping `major` upgrades);
- canonical labels (`type:tech-debt`, `area:infra`, `area:security`).

Alongside it, `.github/workflows/dependabot-auto-merge.yml` calls `joaovpimenta/joaovpimenta/.github/workflows/dependabot-auto-merge.yml@governance-v1.0.0`, which uses SHA-pinned `dependabot/fetch-metadata` without checking out untrusted code and enables squash auto-merge **only** for `dependabot[bot]` PRs classified as `semver-minor` or `semver-patch`, waiting on all required status checks.

## Managed `AGENTS.md` (YAML frontmatter + non-destructive markers)

`governance/defaults/AGENTS.md` defines the canonical agent guidelines with YAML frontmatter (`managed_by`, `policy_version`, `reminder`) reminding coding agents to check the repository's quality, coverage, complexity, and security rules before opening a PR.

Reconciliation rules:

- If `AGENTS.md` does not exist, it is created from the canonical template.
- If `AGENTS.md` contains `<!-- development-hq:start -->` and `<!-- development-hq:end -->`, **only** the bounded section is updated (all repository-specific content outside the markers is preserved untouched).
- If a repository already has a custom `AGENTS.md` without the managed markers, it is **never overwritten** (recorded as a preserved conflict).

## Event-driven enforcement & supply-chain pinning

The controller installs the canonical Issue Form/PR template and thin managed workflow callers in governed repositories:

- `.github/workflows/governance.yml` → `joaovpimenta/joaovpimenta/.github/workflows/governance-event.yml@governance-v1.0.0`
- `.github/workflows/dependabot-auto-merge.yml` → `joaovpimenta/joaovpimenta/.github/workflows/dependabot-auto-merge.yml@governance-v1.0.0`

All external GitHub Actions in governance workflows are pinned by full 40-character commit SHA, and callers pin to the immutable release tag `governance-v1.0.0` rather than a mutable branch. Existing non-managed workflows at the same path are never overwritten.

## Scheduled reconciliation

The central workflow runs at:

- 09:17
- 11:17
- 13:17
- 15:17
- 17:17
- 19:17

America/Sao_Paulo.

It uses a 180-minute overlap window, so a delayed run does not create a gap.

Scheduled reconciliation:

1. discovers governable repositories (respecting fork rules and topics);
2. creates/updates canonical labels;
3. plans managed files (Issue Forms, PR template, `AGENTS.md`, `governance.yml`, `dependabot.yml`, `dependabot-auto-merge.yml`) and applies them via one atomic PR (`chore/governance-sync`) or direct commit, respecting owner-only `safe-only` auto-merge;
4. provisions missing `QLTY_*` / `QUALITY_*` Actions variables on Qlty-enabled repositories;
5. applies free repository hygiene, Dependabot security alerts/fixes, and best-effort Secret Scanning + solo-friendly main-branch Rulesets;
6. normalizes recently changed Issues and reconciles canonical native issue dependencies;
7. syncs changed Issues/PRs into the Project, mirrors metadata/labels into Project fields, and ensures canonical Project views exist.

### Rollout / control variables (optional)

Set as repository variables on `joaovpimenta/joaovpimenta` to customize behavior without code edits:

- `DEVELOPMENT_HQ_IGNORE_FORKS`: `true` (default) or `false`
- `DEVELOPMENT_HQ_WRITE_MODE`: `pr` (default) or `direct`
- `DEVELOPMENT_HQ_AUTO_MERGE`: `safe-only` (default) or `off`
- `DEVELOPMENT_HQ_SYNC_VARIABLES`: `true` (default) or `false`
- `DEVELOPMENT_HQ_SYNC_SETTINGS`: `true` (default) or `false`
- `DEVELOPMENT_HQ_SYNC_RULESETS`: `true` (default) or `false`
- `DEVELOPMENT_HQ_SYNC_DEPENDABOT`: `true` (default) or `false`
- `DEVELOPMENT_HQ_SYNC_AGENTS`: `true` (default) or `false`
- `DEVELOPMENT_HQ_REPO_ALLOWLIST`: optional comma-separated list (e.g. `owner/repo`) to pilot apply runs on a single repository before rolling out globally.
- `DEVELOPMENT_HQ_REPO_DENYLIST`: optional comma-separated list of repositories to exclude.

## Historical retrofit

The manual workflow has a `retrofit_history` mode.

When enabled, it scans all Issues and pull requests, including closed history, rather than only the incremental window.

The retrofit:

- adds historical work to the Project;
- normalizes canonical labels when metadata is unambiguous;
- applies `policy:needs-triage` when metadata cannot be determined safely;
- mirrors historical Type/Area/Organization/Product/Status into the Project;
- converts canonical Blocked by / Blocking references into native GitHub issue dependencies.

Historical body rewriting is intentionally not automatic yet. Existing prose is preserved until a body-migration format is explicitly approved.

## Managed labels

Only the `type:*`, `area:*`, and `policy:*` namespaces are governance-owned.

The reconciler creates and updates canonical managed labels but does not delete unrelated repository-specific labels.

## Security

- Cross-repository access remains in `PROJECT_SCANNER_TOKEN`.
- The public controller never logs repository names, issue titles/bodies, API response bodies, or authorization headers.
- Event workflows in individual repositories use their own `GITHUB_TOKEN` with minimal permissions (`issues: write` for `governance.yml`; `contents: write` + `pull-requests: write` without code checkout for `dependabot-auto-merge.yml`).
- Cross-repository Project writes and dependency reconciliation remain centralized.
- Pure governance policy logic in `scripts/governance-policy.mjs` is verified by `node --test` in `.github/workflows/quality-self-check.yml`.
