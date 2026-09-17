# Development HQ Sync

Central, incremental synchronization of recently changed GitHub issues and pull requests into personal Project #2.

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
- `workflow_dispatch` defaults to dry-run.

## Required secret

Create an Actions secret named `PROJECT_SCANNER_TOKEN`.

The credential must be able to:

1. read the repositories that should be discovered/synchronized;
2. read issues and pull requests in those repositories;
3. read and write the target GitHub Project.

Prefer the narrowest credential your organization policies allow. For organization repositories, the credential may also need organization approval/SSO authorization.

## Optional repository variables

| Variable | Default | Purpose |
|---|---:|---|
| `DEVELOPMENT_HQ_PROJECT_OWNER` | `joaovpimenta` | Project owner login |
| `DEVELOPMENT_HQ_PROJECT_NUMBER` | `2` | Project number |
| `DEVELOPMENT_HQ_LOOKBACK_MINUTES` | `90` | Incremental overlap window |
| `DEVELOPMENT_HQ_MIN_PERMISSION` | `push` | Minimum repo permission (`pull`, `triage`, `push`, `maintain`, `admin`) |
| `DEVELOPMENT_HQ_REPO_ALLOWLIST` | empty | Optional comma-separated `owner/repo` allowlist |
| `DEVELOPMENT_HQ_REPO_DENYLIST` | empty | Optional comma-separated `owner/repo` denylist |
| `DEVELOPMENT_HQ_INCLUDE_ISSUES` | `true` | Include issues |
| `DEVELOPMENT_HQ_INCLUDE_PRS` | `true` | Include pull requests |
| `DEVELOPMENT_HQ_LOG_LEVEL` | `info` | `info` or sanitized `debug` |

For maximum control, set an explicit allowlist. Leave it empty only if the intended policy is to include every accessible repository meeting the permission threshold.

## First run

1. Add the required secret.
2. Optionally configure an allowlist/denylist and other variables.
3. Run **Development HQ Sync** manually with `dry_run=true`.
4. Inspect only aggregate counts in the log.
5. Run again with `dry_run=false` when the counts are expected.

The scheduled run executes hourly at minute 17 and uses a 90-minute lookback by default. The overlap intentionally makes the sync tolerant of delays; adding an item already in the Project does not create a second Project item.

## Scope of this first version

This version safely discovers eligible repositories and adds recently changed issues/PRs to the Project. Project Status reconciliation is intentionally not enabled yet. Status rules should be added after the ingestion path has been validated, so automation cannot overwrite manual workflow state unexpectedly.
