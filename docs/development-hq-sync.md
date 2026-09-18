# Development HQ Sync

Central synchronization of GitHub issues and pull requests into personal Project #2.

## Behavior

The sync has two modes:

1. **Open backfill**: scans every open issue and pull request in every eligible repository and adds anything missing from the Project.
2. **Incremental sync**: scans only repository-scoped issues and pull requests updated inside the overlap window (90 minutes by default).

The repository-scoped incremental scan avoids the previous global GitHub Search behavior that could inspect large numbers of unrelated public items.

Before writes, the script loads the current Project content IDs. Existing items are skipped, so repeated backfills and overlapping incremental runs are idempotent.

## Security model

- No credential is committed to the repository.
- The workflow uses only `secrets.PROJECT_SCANNER_TOKEN` for cross-repository/Projects access.
- The built-in `GITHUB_TOKEN` has only `contents: read`.
- Checkout credentials are not persisted.
- Shell tracing is disabled before handling the token.
- The token is explicitly masked with `::add-mask::`.
- The script never logs issue/PR titles, bodies, comments, raw API payloads, authorization headers, or private repository names.
- Errors are sanitized. `LOG_LEVEL=debug` does not enable raw payload logging.
- No artifacts or caches contain credentials or API responses.
- Manual runs default to dry-run.
- Scheduled runs remain dry-run unless `DEVELOPMENT_HQ_APPLY_ENABLED=true`.

## Required secret

Create an Actions secret named `PROJECT_SCANNER_TOKEN`.

The credential must be able to:

1. read the repositories that should be discovered/synchronized;
2. read issues and pull requests in those repositories;
3. read and write the target GitHub Project.

For organization repositories, the credential may also need organization approval/SSO authorization.

## Optional repository variables

| Variable | Default | Purpose |
|---|---:|---|
| `DEVELOPMENT_HQ_PROJECT_OWNER` | `joaovpimenta` | Project owner login |
| `DEVELOPMENT_HQ_PROJECT_NUMBER` | `2` | Project number |
| `DEVELOPMENT_HQ_LOOKBACK_MINUTES` | `90` | Incremental overlap window |
| `DEVELOPMENT_HQ_MIN_PERMISSION` | `push` | Minimum repo permission |
| `DEVELOPMENT_HQ_REPO_ALLOWLIST` | empty | Optional comma-separated `owner/repo` allowlist |
| `DEVELOPMENT_HQ_REPO_DENYLIST` | empty | Optional comma-separated `owner/repo` denylist |
| `DEVELOPMENT_HQ_INCLUDE_ISSUES` | `true` | Include issues |
| `DEVELOPMENT_HQ_INCLUDE_PRS` | `true` | Include pull requests |
| `DEVELOPMENT_HQ_LOG_LEVEL` | `info` | `info` or sanitized `debug` |
| `DEVELOPMENT_HQ_APPLY_ENABLED` | `false` | Allow scheduled runs to write |

## Manual runs

For a normal validation run:

- `dry_run=true`
- `backfill_open=false`

For a one-time open-work backfill:

- first run `dry_run=true`, `backfill_open=true`;
- then run `dry_run=false`, `backfill_open=true` after validating aggregate counts.

The scheduled run executes hourly at minute 17 and uses the incremental window.

## Current scope

The sync ingests issues and pull requests into the Project. Project Status reconciliation is intentionally separate so ingestion cannot overwrite manual workflow state.
