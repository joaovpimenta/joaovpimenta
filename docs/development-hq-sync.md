# Development HQ Sync

Central synchronization and governance of GitHub issues and pull requests into personal Project #2.

## Execution model

The workflow now has three coordinated stages:

1. **Governance reconciliation** — labels, event callers, owner-level default templates, recent Issue normalization, and native dependency reconciliation.
2. **Project ingestion** — repository-scoped addition of Issues/PRs to the central Project.
3. **Project metadata reconciliation** — canonical fields, metadata mirroring, status migration, and canonical views.

See `docs/governance.md` for the full policy and ownership model.

## Modes

- **Incremental**: scans items changed inside the overlap window.
- **Open backfill**: scans all open Issues and PRs.
- **Full historical retrofit**: scans all Issues and PRs, including closed items.

Manual runs default to dry-run.

## Schedule

The scheduled workflow runs every two hours during the working day at 09:17, 11:17, 13:17, 15:17, 17:17, and 19:17 America/Sao_Paulo.

The default incremental overlap is 180 minutes.

## Security model

- No credential is committed to the repository.
- The workflow uses only `secrets.PROJECT_SCANNER_TOKEN` for cross-repository/Projects access.
- The built-in `GITHUB_TOKEN` has only `contents: read` in the controller.
- Checkout credentials are not persisted.
- Shell tracing is disabled before handling the token.
- The token is explicitly masked.
- Scripts never log issue/PR titles, bodies, raw API payloads, authorization headers, or private repository names.
- Push-triggered validation remains dry-run.
- Scheduled runs apply incremental reconciliation automatically.

## Required secret

`PROJECT_SCANNER_TOKEN` must be able to:

1. read governed repositories;
2. read/write Issues and labels in governed repositories;
3. create/update the managed governance workflow file;
4. read/write the target GitHub Project.

The existing classic PAT also needs the `workflow` scope to install managed workflow files. Organization repositories may require SSO authorization.

## Optional variables

| Variable | Default | Purpose |
|---|---:|---|
| `DEVELOPMENT_HQ_PROJECT_OWNER` | `joaovpimenta` | Personal Project owner |
| `DEVELOPMENT_HQ_PROJECT_NUMBER` | `2` | Project number |
| `DEVELOPMENT_HQ_LOOKBACK_MINUTES` | `180` | Incremental overlap window |
| `DEVELOPMENT_HQ_MIN_PERMISSION` | `push` | Minimum permission for Project ingestion |
| `DEVELOPMENT_HQ_REPO_ALLOWLIST` | empty | Optional allowlist |
| `DEVELOPMENT_HQ_REPO_DENYLIST` | empty | Optional denylist |
| `DEVELOPMENT_HQ_INCLUDE_ISSUES` | `true` | Include Issues |
| `DEVELOPMENT_HQ_INCLUDE_PRS` | `true` | Include pull requests |
| `DEVELOPMENT_HQ_LOG_LEVEL` | `info` | Sanitized logging level |

No repository registration is required when allowlist/denylist are empty.

## Bootstrap required outside this repository

Create one public `.github` repository for every owner whose repositories should inherit the default Issue Form/PR template.

For the current structure this means at least:

- the personal account `.github` repository;
- the Glucontinuum organization `.github` repository.

After those repositories exist, the controller populates and maintains their template files automatically.
