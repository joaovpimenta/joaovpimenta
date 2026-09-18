# Development HQ Governance

This repository is the control plane and source of truth for issue/project governance.

## Repository roles

### joaovpimenta/joaovpimenta

The controller repository owns:

- the canonical taxonomy in `governance/taxonomy.json`;
- canonical Issue Form and pull request templates under `governance/defaults`;
- the reusable issue-event workflow;
- the central repository reconciler;
- the Project metadata reconciler;
- the scheduled sync and historical retrofit entry point.

No repository names are registered manually. Repositories are discovered dynamically from the token.

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

## Event-driven enforcement

The controller installs the canonical Issue Form/PR template and a tiny managed workflow directly in governed repositories. The workflow lives at:

`.github/workflows/governance.yml`.

That caller invokes the public reusable workflow in this controller. The event workflow runs on Issue create/edit/reopen/label changes and reconciles Type/Area labels immediately using the Issue Form body.

The thin caller is generated and updated automatically. Existing non-managed workflows at the same path are never overwritten.

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

1. discovers governable repositories;
2. creates/updates canonical labels;
3. installs/updates managed event callers;
4. normalizes recently changed Issues;
5. reconciles canonical native issue dependencies;
6. syncs changed Issues/PRs into the Project;
7. creates/reconciles Project fields;
8. mirrors repository metadata/labels into Project fields;
9. creates missing canonical Project views.

## Governed repository scope

The governance writer intentionally uses a stricter scope than the Project reader.

A repository is governed when:

- it is not archived or disabled;
- the token has push access; and
- it is owned by the personal Project owner, or it is organization-owned and the token reports admin access.

This prevents governance from being pushed into unrelated personal collaborator repositories merely because the user can contribute to them.

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
- Event workflows in individual repositories use their own `GITHUB_TOKEN` and require only `issues: write`.
- Cross-repository Project writes and dependency reconciliation remain centralized.
