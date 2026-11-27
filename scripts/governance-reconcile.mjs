import fs from 'node:fs';
import {
  GOVERNANCE_SYNC_BRANCH,
  MAIN_RULESET_NAME,
  MANAGED_HTML_MARKER,
  MANAGED_YAML_MARKER,
  TOPIC_NO_RULESET,
  TOPIC_QLTY_ENABLED,
  buildDependabotConfig,
  buildMainBranchRulesetPayload,
  computeQualityVariablePlan,
  detectRepoStack,
  evaluateGovernanceAutoMergeEligibility,
  normalizeTopics,
  reconcileAgentsMd,
  resolveRequiredStatusChecks,
  shouldGovernRepo,
} from './governance-policy.mjs';

class SafeError extends Error {}

const token = required('GH_TOKEN');
const projectOwner = env('PROJECT_OWNER', 'joaovpimenta');
const lookbackMinutes = intEnv('LOOKBACK_MINUTES', 180, 30, 10080);
const dryRun = boolEnv('DRY_RUN', false);
const retrofitHistory = boolEnv('RETROFIT_HISTORY', false);
const ignoreForks = boolEnv('GOVERNANCE_IGNORE_FORKS', true);
const writeMode = choiceEnv('GOVERNANCE_WRITE_MODE', ['pr', 'direct'], 'pr');
const autoMergeMode = choiceEnv('GOVERNANCE_AUTO_MERGE', ['off', 'safe-only', 'all'], 'safe-only');
const syncVariables = boolEnv('GOVERNANCE_SYNC_VARIABLES', true);
const syncSettings = boolEnv('GOVERNANCE_SYNC_SETTINGS', true);
const syncRulesets = boolEnv('GOVERNANCE_SYNC_RULESETS', true);
const syncDependabot = boolEnv('GOVERNANCE_SYNC_DEPENDABOT', true);
const syncAgents = boolEnv('GOVERNANCE_SYNC_AGENTS', true);
const allowlist = csvSet('REPO_ALLOWLIST');
const denylist = csvSet('REPO_DENYLIST');
const policy = JSON.parse(fs.readFileSync('governance/taxonomy.json', 'utf8'));
const qualityDefaults = JSON.parse(fs.readFileSync('governance/quality-defaults.json', 'utf8'));

const CONTROLLER_FULL_NAME = `${projectOwner}/${projectOwner}`.toLowerCase();

process.stdout.write(`::add-mask::${token}\n`);

const counters = {
  discovered: 0,
  governed: 0,
  labelsCreated: 0,
  labelsUpdated: 0,
  filesPlanned: 0,
  fileConflicts: 0,
  syncPrsCreated: 0,
  syncPrsUpdated: 0,
  syncPrsUnchanged: 0,
  directCommits: 0,
  autoMergeEnabled: 0,
  autoMergeSkipped: 0,
  variablesCreated: 0,
  variablesUpdated: 0,
  variablesPermissionSkipped: 0,
  repoSettingsUpdated: 0,
  securityFeaturesEnabled: 0,
  rulesetsCreated: 0,
  rulesetsUpdated: 0,
  rulesetsPlanSkipped: 0,
  emptyRepositoriesDeferred: 0,
  ownerDefaultsSynced: 0,
  ownerDefaultsMissing: 0,
  ownerDefaultsInvalid: 0,
  issuesScanned: 0,
  issuesNormalized: 0,
  needsTriage: 0,
  dependencyLinksAttempted: 0,
  errors: 0,
};

try {
  const repos = await listRepos();
  counters.discovered = repos.length;

  const governed = repos.filter((repo) =>
    shouldGovernRepo(repo, { projectOwner, ignoreForks, allowlist, denylist }),
  );
  counters.governed = governed.length;

  for (const repo of governed) {
    try {
      await ensureLabels(repo);
      if (repo.name !== '.github') {
        if (Number(repo.size || 0) === 0) {
          counters.emptyRepositoriesDeferred++;
        } else {
          const context = await inspectRepositoryContext(repo);
          const pendingChanges = await collectManagedFileChanges(repo, context);
          if (pendingChanges.length > 0) {
            counters.filesPlanned += pendingChanges.length;
            await applyPendingFileChanges(repo, pendingChanges);
          }
          if (syncVariables) {
            await ensureQualityVariables(repo, context);
          }
          if (syncSettings) {
            await ensureRepoSettingsAndRuleset(repo, context);
          }
        }
      }
      await normalizeRecentIssues(repo);
    } catch (error) {
      counters.errors++;
      safeError('Repository governance failed', error);
    }
  }

  const owners = unique(governed.map((r) => r.owner?.login).filter(Boolean));
  for (const owner of owners) {
    try {
      await syncOwnerDefaults(owner);
    } catch (error) {
      counters.errors++;
      safeError('Owner defaults sync failed', error);
    }
  }
} catch (error) {
  counters.errors++;
  safeError('Governance reconciliation failed', error);
  process.exitCode = 1;
} finally {
  console.log('Development HQ Governance');
  console.log(`Repositories discovered: ${counters.discovered}`);
  console.log(`Repositories governed: ${counters.governed}`);
  console.log(`Labels created: ${counters.labelsCreated}`);
  console.log(`Labels updated: ${counters.labelsUpdated}`);
  console.log(`Managed files planned: ${counters.filesPlanned}`);
  console.log(`Managed file conflicts (preserved): ${counters.fileConflicts}`);
  console.log(`Sync PRs created: ${counters.syncPrsCreated}`);
  console.log(`Sync PRs updated: ${counters.syncPrsUpdated}`);
  console.log(`Sync PRs unchanged: ${counters.syncPrsUnchanged}`);
  console.log(`Direct atomic commits: ${counters.directCommits}`);
  console.log(`Auto-merge enabled: ${counters.autoMergeEnabled}`);
  console.log(`Auto-merge skipped: ${counters.autoMergeSkipped}`);
  console.log(`QLTY variables created: ${counters.variablesCreated}`);
  console.log(`QLTY variables updated: ${counters.variablesUpdated}`);
  console.log(`QLTY variables skipped (permission): ${counters.variablesPermissionSkipped}`);
  console.log(`Repo settings updated: ${counters.repoSettingsUpdated}`);
  console.log(`Security features enabled: ${counters.securityFeaturesEnabled}`);
  console.log(`Rulesets created: ${counters.rulesetsCreated}`);
  console.log(`Rulesets updated: ${counters.rulesetsUpdated}`);
  console.log(`Rulesets skipped (plan/opt-out): ${counters.rulesetsPlanSkipped}`);
  console.log(`Empty repositories deferred: ${counters.emptyRepositoriesDeferred}`);
  console.log(`Owner defaults synced: ${counters.ownerDefaultsSynced}`);
  console.log(`Owner defaults missing: ${counters.ownerDefaultsMissing}`);
  console.log(`Owner defaults invalid: ${counters.ownerDefaultsInvalid}`);
  console.log(`Issues scanned: ${counters.issuesScanned}`);
  console.log(`Issues normalized: ${counters.issuesNormalized}`);
  console.log(`Needs triage: ${counters.needsTriage}`);
  console.log(`Dependency links attempted: ${counters.dependencyLinksAttempted}`);
  console.log(`Errors: ${counters.errors}`);
  console.log(`Write mode: ${writeMode} (auto-merge: ${autoMergeMode})`);
  console.log(`Scope: ${retrofitHistory ? 'FULL HISTORY' : `INCREMENTAL ${lookbackMinutes}m`}`);
  console.log(`Mode: ${dryRun ? 'DRY RUN' : 'APPLY'}`);
}

async function listRepos() {
  const out = [];
  for (let page = 1; page <= 100; page++) {
    const batch = await rest(
      `/user/repos?per_page=100&page=${page}&affiliation=owner,collaborator,organization_member&sort=updated`,
    );
    out.push(...batch);
    if (batch.length < 100) break;
  }
  return out;
}

async function inspectRepositoryContext(repo) {
  const rootListing = await getRootEntries(repo.full_name);
  const rootNames = new Set(rootListing.map((e) => String(e.name || '').toLowerCase()));

  let packageJson = null;
  if (rootNames.has('package.json')) {
    const file = await getContent(repo.full_name, 'package.json');
    if (file) {
      try {
        packageJson = JSON.parse(decodeContent(file));
      } catch {
        packageJson = null;
      }
    }
  }

  let gradleHasAndroid = false;
  for (const gradleFile of ['build.gradle.kts', 'build.gradle', 'app/build.gradle.kts', 'app/build.gradle']) {
    if (gradleFile.startsWith('app/') && !rootNames.has('app')) continue;
    if (!gradleFile.startsWith('app/') && !rootNames.has(gradleFile)) continue;
    const file = await getContent(repo.full_name, gradleFile);
    if (file && /com\.android\.(?:application|library)/i.test(decodeContent(file))) {
      gradleHasAndroid = true;
      break;
    }
  }

  const stackInfo = detectRepoStack(rootListing, { packageJson, gradleHasAndroid });
  const qltyConfig = await getContent(repo.full_name, '.qlty/qlty.toml');
  const hasQltyConfig = Boolean(qltyConfig);
  const topics = normalizeTopics(repo);
  const existingVars = await listRepoVariablesSafe(repo.full_name);

  return {
    stackInfo,
    hasQltyConfig,
    topics,
    existingVars,
  };
}

async function getRootEntries(fullName) {
  try {
    const data = await rest(`/repos/${fullName}/contents`);
    return Array.isArray(data) ? data : [];
  } catch (error) {
    if (error instanceof SafeError && (error.status === 404 || error.status === 409)) return [];
    throw error;
  }
}

async function collectManagedFileChanges(repo, context) {
  const isController = repo.full_name.toLowerCase() === CONTROLLER_FULL_NAME;
  const managedFiles = [
    {
      path: '.github/workflows/governance.yml',
      content: readUtf8Lf('governance/defaults/governance-caller.yml'),
      marker: MANAGED_YAML_MARKER,
    },
    {
      path: '.github/ISSUE_TEMPLATE/work-item.yml',
      content: readUtf8Lf('governance/defaults/ISSUE_TEMPLATE/work-item.yml'),
      marker: MANAGED_YAML_MARKER,
    },
    {
      path: '.github/ISSUE_TEMPLATE/config.yml',
      content: readUtf8Lf('governance/defaults/ISSUE_TEMPLATE/config.yml'),
      marker: MANAGED_YAML_MARKER,
    },
    {
      path: '.github/PULL_REQUEST_TEMPLATE.md',
      content: readUtf8Lf('governance/defaults/PULL_REQUEST_TEMPLATE.md'),
      marker: MANAGED_HTML_MARKER,
    },
  ];

  if (syncDependabot) {
    managedFiles.push({
      path: '.github/dependabot.yml',
      content: normalizeLf(buildDependabotConfig(context.stackInfo)),
      marker: MANAGED_YAML_MARKER,
    });
    if (!isController) {
      managedFiles.push({
        path: '.github/workflows/dependabot-auto-merge.yml',
        content: readUtf8Lf('governance/defaults/dependabot-auto-merge-caller.yml'),
        marker: MANAGED_YAML_MARKER,
      });
    }
  }

  const pending = [];

  for (const spec of managedFiles) {
    const existing = await getContent(repo.full_name, spec.path);
    if (!existing) {
      pending.push({ path: spec.path, content: spec.content });
      continue;
    }
    const current = normalizeLf(decodeContent(existing));
    if (current === spec.content) continue;
    if (!current.startsWith(spec.marker)) {
      counters.fileConflicts++;
      continue;
    }
    pending.push({ path: spec.path, content: spec.content });
  }

  if (syncAgents) {
    const agentsTemplate = readUtf8Lf('governance/defaults/AGENTS.md');
    const existingAgents = await getContent(repo.full_name, 'AGENTS.md');
    const existingText = existingAgents ? normalizeLf(decodeContent(existingAgents)) : null;
    const result = reconcileAgentsMd(existingText, agentsTemplate);
    if (result.action === 'create' || result.action === 'update') {
      pending.push({ path: 'AGENTS.md', content: normalizeLf(result.content) });
    } else if (result.action === 'conflict') {
      counters.fileConflicts++;
    }
  }

  return pending;
}

async function applyPendingFileChanges(repo, pendingChanges) {
  const defaultBranch = repo.default_branch || 'main';
  if (writeMode === 'direct') {
    counters.directCommits++;
    if (dryRun) return;
    await commitFilesAtomically(
      repo.full_name,
      defaultBranch,
      defaultBranch,
      pendingChanges,
      'chore(governance): sync managed repository files',
      false,
    );
    return;
  }

  // PR mode: 1 atomic branch & PR per repository.
  const openPr = await findOpenGovernanceSyncPr(repo, defaultBranch);
  if (openPr) {
    const alreadySyncedOnBranch = await branchMatchesPendingChanges(
      repo.full_name,
      GOVERNANCE_SYNC_BRANCH,
      pendingChanges,
    );
    if (alreadySyncedOnBranch) {
      counters.syncPrsUnchanged++;
      if (!dryRun) {
        await maybeEnableGovernanceAutoMerge(repo, openPr);
      }
      return;
    }
    counters.syncPrsUpdated++;
    if (dryRun) return;
    await commitFilesAtomically(
      repo.full_name,
      defaultBranch,
      GOVERNANCE_SYNC_BRANCH,
      pendingChanges,
      'chore(governance): sync managed repository files',
      true,
    );
    await maybeEnableGovernanceAutoMerge(repo, openPr);
    return;
  }

  counters.syncPrsCreated++;
  if (dryRun) return;

  await commitFilesAtomically(
    repo.full_name,
    defaultBranch,
    GOVERNANCE_SYNC_BRANCH,
    pendingChanges,
    'chore(governance): sync managed repository files',
    true,
  );

  const fileList = pendingChanges.map((item) => `- \`${item.path}\``).join('\n');
  const pr = await rest(`/repos/${repo.full_name}/pulls`, {
    method: 'POST',
    body: {
      title: 'chore(governance): sync managed repository files',
      head: GOVERNANCE_SYNC_BRANCH,
      base: defaultBranch,
      body: [
        '<!-- managed-by: development-hq-governance -->',
        'Sincronização atômica de arquivos gerenciados pelo control plane `joaovpimenta/joaovpimenta`.',
        '',
        '### Arquivos atualizados',
        fileList,
      ].join('\n'),
    },
  });

  await request(`/repos/${repo.full_name}/issues/${pr.number}/labels`, {
    method: 'POST',
    body: { labels: ['type:tech-debt', 'area:infra'] },
  });

  await maybeEnableGovernanceAutoMerge(repo, pr);
}

async function branchMatchesPendingChanges(fullName, branch, pendingChanges) {
  for (const change of pendingChanges) {
    const file = await getContent(fullName, change.path, branch);
    if (!file || decodeContent(file) !== change.content) {
      return false;
    }
  }
  return true;
}

async function commitFilesAtomically(fullName, baseBranch, targetBranch, changes, message, forceUpdate) {
  const baseRef = await rest(`/repos/${fullName}/git/ref/heads/${encodeURIComponent(baseBranch)}`);
  const baseCommitSha = baseRef.object.sha;
  const baseCommit = await rest(`/repos/${fullName}/git/commits/${baseCommitSha}`);
  const baseTreeSha = baseCommit.tree.sha;

  const treeEntries = [];
  for (const item of changes) {
    const blob = await rest(`/repos/${fullName}/git/blobs`, {
      method: 'POST',
      body: {
        content: item.content,
        encoding: 'utf-8',
      },
    });
    treeEntries.push({
      path: item.path,
      mode: '100644',
      type: 'blob',
      sha: blob.sha,
    });
  }

  const newTree = await rest(`/repos/${fullName}/git/trees`, {
    method: 'POST',
    body: {
      base_tree: baseTreeSha,
      tree: treeEntries,
    },
  });

  const newCommit = await rest(`/repos/${fullName}/git/commits`, {
    method: 'POST',
    body: {
      message,
      tree: newTree.sha,
      parents: [baseCommitSha],
    },
  });

  const existingTarget = await getGitRef(fullName, `heads/${targetBranch}`);
  if (existingTarget) {
    await rest(`/repos/${fullName}/git/refs/heads/${encodeURIComponent(targetBranch)}`, {
      method: 'PATCH',
      body: { sha: newCommit.sha, force: Boolean(forceUpdate) },
    });
  } else {
    await rest(`/repos/${fullName}/git/refs`, {
      method: 'POST',
      body: { ref: `refs/heads/${targetBranch}`, sha: newCommit.sha },
    });
  }
}

async function getGitRef(fullName, refSuffix) {
  const res = await request(`/repos/${fullName}/git/ref/${refSuffix}`);
  if (res.status === 404) return null;
  if (!res.ok) {
    const error = new SafeError(`GitHub git/ref request failed (${res.status}).`);
    error.status = res.status;
    throw error;
  }
  return res.json();
}

async function findOpenGovernanceSyncPr(repo, defaultBranch) {
  const head = `${repo.owner.login}:${GOVERNANCE_SYNC_BRANCH}`;
  const prs = await rest(
    `/repos/${repo.full_name}/pulls?state=open&head=${encodeURIComponent(head)}&base=${encodeURIComponent(defaultBranch)}&per_page=10`,
  );
  return Array.isArray(prs) && prs.length > 0 ? prs[0] : null;
}

async function maybeEnableGovernanceAutoMerge(repo, pr) {
  const files = await rest(`/repos/${repo.full_name}/pulls/${pr.number}/files?per_page=100`);
  const commits = await rest(`/repos/${repo.full_name}/pulls/${pr.number}/commits?per_page=100`);
  const changedFiles = (Array.isArray(files) ? files : []).map((f) => f.filename);

  const decision = evaluateGovernanceAutoMergeEligibility({
    mode: autoMergeMode,
    repo,
    pr,
    changedFiles,
    commits: Array.isArray(commits) ? commits : [],
  });

  if (!decision.eligible) {
    counters.autoMergeSkipped++;
    return;
  }

  try {
    await graphql(
      `mutation($pullRequestId: ID!) {
        enablePullRequestAutoMerge(input: { pullRequestId: $pullRequestId, mergeMethod: SQUASH }) {
          pullRequest { number }
        }
      }`,
      { pullRequestId: pr.node_id },
    );
    counters.autoMergeEnabled++;
  } catch {
    // Auto-merge can fail gracefully when repo has no branch protection/ruleset yet (e.g. private Free plan).
    counters.autoMergeSkipped++;
  }
}

async function listRepoVariablesSafe(fullName) {
  try {
    const data = await rest(`/repos/${fullName}/actions/variables?per_page=100`);
    const map = {};
    for (const item of data?.variables || []) {
      map[item.name] = item.value;
    }
    return map;
  } catch (error) {
    if (error instanceof SafeError && (error.status === 403 || error.status === 404)) {
      return null;
    }
    throw error;
  }
}

async function ensureQualityVariables(repo, context) {
  if (!context.hasQltyConfig && !context.topics.has(TOPIC_QLTY_ENABLED)) return;
  if (context.existingVars === null) {
    counters.variablesPermissionSkipped++;
    return;
  }

  const plan = computeQualityVariablePlan(context.existingVars, context.stackInfo, qualityDefaults);

  for (const item of plan.create) {
    counters.variablesCreated++;
    if (dryRun) continue;
    const res = await request(`/repos/${repo.full_name}/actions/variables`, {
      method: 'POST',
      body: { name: item.name, value: item.value },
    });
    if (res.status === 403) {
      counters.variablesPermissionSkipped++;
      return;
    }
    if (!res.ok) {
      throw new SafeError(`Variable create failed (${res.status}).`);
    }
  }

  for (const item of plan.update) {
    counters.variablesUpdated++;
    if (dryRun) continue;
    const res = await request(
      `/repos/${repo.full_name}/actions/variables/${encodeURIComponent(item.name)}`,
      {
        method: 'PATCH',
        body: { name: item.name, value: item.value },
      },
    );
    if (res.status === 403) {
      counters.variablesPermissionSkipped++;
      return;
    }
    if (!res.ok) {
      throw new SafeError(`Variable update failed (${res.status}).`);
    }
  }
}

async function ensureRepoSettingsAndRuleset(repo, context) {
  const needsRepoPatch =
    repo.delete_branch_on_merge !== true ||
    repo.allow_auto_merge !== true ||
    repo.allow_squash_merge !== true;

  if (needsRepoPatch) {
    counters.repoSettingsUpdated++;
    if (!dryRun) {
      const patchBody = {
        delete_branch_on_merge: true,
        allow_auto_merge: true,
        allow_squash_merge: true,
      };
      if (!repo.private) {
        patchBody.security_and_analysis = {
          secret_scanning: { status: 'enabled' },
          secret_scanning_push_protection: { status: 'enabled' },
        };
      }
      const res = await request(`/repos/${repo.full_name}`, {
        method: 'PATCH',
        body: patchBody,
      });
      if (res.status === 422 && patchBody.security_and_analysis) {
        delete patchBody.security_and_analysis;
        await rest(`/repos/${repo.full_name}`, { method: 'PATCH', body: patchBody });
      } else if (!res.ok && res.status !== 403) {
        throw new SafeError(`Repository settings update failed (${res.status}).`);
      }
    }
  }

  // Dependabot vulnerability alerts + automated security fixes (free on public and private repos).
  if (!dryRun) {
    const alertsRes = await request(`/repos/${repo.full_name}/vulnerability-alerts`, { method: 'PUT' });
    if (alertsRes.ok) counters.securityFeaturesEnabled++;
    const fixesRes = await request(`/repos/${repo.full_name}/automated-security-fixes`, { method: 'PUT' });
    if (fixesRes.ok) counters.securityFeaturesEnabled++;
  }

  if (!syncRulesets || context.topics.has(TOPIC_NO_RULESET)) {
    counters.rulesetsPlanSkipped++;
    return;
  }

  const listRes = await request(`/repos/${repo.full_name}/rulesets?includes_parents=false`);
  if (listRes.status === 403 || listRes.status === 404) {
    counters.rulesetsPlanSkipped++;
    return;
  }
  if (!listRes.ok) {
    throw new SafeError(`Rulesets list failed (${listRes.status}).`);
  }

  const rulesets = await listRes.json();
  const existing = (Array.isArray(rulesets) ? rulesets : []).find((r) => r.name === MAIN_RULESET_NAME);
  const requiredChecks = resolveRequiredStatusChecks({
    hasQltyConfig: context.hasQltyConfig,
    existingVars: context.existingVars || {},
  });
  const desired = buildMainBranchRulesetPayload({ name: MAIN_RULESET_NAME, requiredChecks });

  if (!existing) {
    counters.rulesetsCreated++;
    if (dryRun) return;
    const createRes = await request(`/repos/${repo.full_name}/rulesets`, {
      method: 'POST',
      body: desired,
    });
    if (createRes.status === 403 || createRes.status === 422) {
      counters.rulesetsPlanSkipped++;
      return;
    }
    if (!createRes.ok) {
      throw new SafeError(`Ruleset create failed (${createRes.status}).`);
    }
    return;
  }

  // Fetch full ruleset details to compare before updating.
  const fullExisting = await rest(`/repos/${repo.full_name}/rulesets/${existing.id}`);
  if (rulesetMatches(fullExisting, desired)) return;

  counters.rulesetsUpdated++;
  if (dryRun) return;
  const updateRes = await request(`/repos/${repo.full_name}/rulesets/${existing.id}`, {
    method: 'PUT',
    body: desired,
  });
  if (updateRes.status === 403 || updateRes.status === 422) {
    counters.rulesetsPlanSkipped++;
    return;
  }
  if (!updateRes.ok) {
    throw new SafeError(`Ruleset update failed (${updateRes.status}).`);
  }
}

function rulesetMatches(existing, desired) {
  if (!existing) return false;
  if (existing.enforcement !== desired.enforcement) return false;
  const existingTypes = (existing.rules || []).map((r) => r.type).sort();
  const desiredTypes = (desired.rules || []).map((r) => r.type).sort();
  if (JSON.stringify(existingTypes) !== JSON.stringify(desiredTypes)) return false;

  const existingChecks = (
    existing.rules?.find((r) => r.type === 'required_status_checks')?.parameters?.required_status_checks || []
  )
    .map((c) => c.context)
    .sort();
  const desiredChecks = (
    desired.rules?.find((r) => r.type === 'required_status_checks')?.parameters?.required_status_checks || []
  )
    .map((c) => c.context)
    .sort();

  return JSON.stringify(existingChecks) === JSON.stringify(desiredChecks);
}

async function ensureLabels(repo) {
  const desired = [
    ...(policy.type || []),
    ...(policy.area || []),
    ...(policy.policyLabels || []),
  ];

  const current = await listLabels(repo.full_name);
  const byName = new Map(current.map((x) => [x.name.toLowerCase(), x]));

  for (const def of desired) {
    const found = byName.get(def.label.toLowerCase());
    if (!found) {
      counters.labelsCreated++;
      if (!dryRun) {
        await rest(`/repos/${repo.full_name}/labels`, {
          method: 'POST',
          body: { name: def.label, color: def.color, description: def.description },
        });
      }
      continue;
    }

    const differs =
      String(found.color || '').toLowerCase() !== String(def.color || '').toLowerCase() ||
      String(found.description || '') !== String(def.description || '');

    if (differs) {
      counters.labelsUpdated++;
      if (!dryRun) {
        await rest(`/repos/${repo.full_name}/labels/${encodeURIComponent(found.name)}`, {
          method: 'PATCH',
          body: {
            new_name: def.label,
            color: def.color,
            description: def.description,
          },
        });
      }
    }
  }
}

async function listLabels(fullName) {
  const out = [];
  for (let page = 1; page <= 20; page++) {
    const batch = await rest(`/repos/${fullName}/labels?per_page=100&page=${page}`);
    out.push(...batch);
    if (batch.length < 100) break;
  }
  return out;
}

async function syncOwnerDefaults(owner) {
  const repoName = `${owner}/.github`;
  let metadata;
  try {
    metadata = await rest(`/repos/${repoName}`);
  } catch (error) {
    if (error instanceof SafeError && error.status === 404) {
      counters.ownerDefaultsMissing++;
      return;
    }
    throw error;
  }

  if (metadata.private || metadata.visibility === 'private') {
    counters.ownerDefaultsInvalid++;
    return;
  }

  const files = [
    ['.github/ISSUE_TEMPLATE/work-item.yml', 'governance/defaults/ISSUE_TEMPLATE/work-item.yml'],
    ['.github/ISSUE_TEMPLATE/config.yml', 'governance/defaults/ISSUE_TEMPLATE/config.yml'],
    ['.github/PULL_REQUEST_TEMPLATE.md', 'governance/defaults/PULL_REQUEST_TEMPLATE.md'],
  ];

  let changed = false;
  for (const [target, source] of files) {
    const desired = readUtf8Lf(source);
    const existing = await getContent(repoName, target);
    if (existing && normalizeLf(decodeContent(existing)) === desired) continue;

    changed = true;
    if (!dryRun) {
      await putContent(
        repoName,
        target,
        desired,
        existing ? 'chore: update default governance template' : 'chore: add default governance template',
        existing?.sha,
      );
    }
  }

  if (changed) counters.ownerDefaultsSynced++;
}

async function normalizeRecentIssues(repo) {
  const items = await listIssues(repo.full_name);
  for (const issue of items) {
    if (issue.pull_request) continue;
    counters.issuesScanned++;

    try {
      const result = desiredLabelsForIssue(issue);
      if (result.needsTriage) counters.needsTriage++;

      if (!sameSet(result.current, result.desired)) {
        counters.issuesNormalized++;
        if (!dryRun) {
          await rest(`/repos/${repo.full_name}/issues/${issue.number}/labels`, {
            method: 'PUT',
            body: { labels: result.desired },
          });
        }
      }

      await reconcileDependencies(repo.full_name, issue);
    } catch (error) {
      counters.errors++;
      safeError('Issue normalization failed', error);
    }
  }
}

async function listIssues(fullName) {
  const out = [];
  for (let page = 1; page <= 100; page++) {
    const params = new URLSearchParams({
      state: 'all',
      sort: 'updated',
      direction: 'desc',
      per_page: '100',
      page: String(page),
    });

    if (!retrofitHistory) {
      const since = new Date(Date.now() - lookbackMinutes * 60_000).toISOString();
      params.set('since', since);
    }

    const batch = await rest(`/repos/${fullName}/issues?${params.toString()}`);
    out.push(...batch);
    if (batch.length < 100) break;
  }
  return out;
}

function desiredLabelsForIssue(issue) {
  const typeDefs = policy.type || [];
  const areaDefs = policy.area || [];
  const triageLabel = policy.rules?.unknownMetadataLabel || 'policy:needs-triage';
  const managed = new Set([
    ...typeDefs.map((x) => x.label),
    ...areaDefs.map((x) => x.label),
    ...(policy.policyLabels || []).map((x) => x.label),
  ]);

  const current = (issue.labels || []).map((x) => (typeof x === 'string' ? x : x.name)).filter(Boolean);
  const currentTypes = current.filter((x) => typeDefs.some((d) => eq(d.label, x)));
  const currentAreas = current.filter((x) => areaDefs.some((d) => eq(d.label, x)));

  const typeSection = readSection(issue.body || '', 'Type');
  const areaSection = readSection(issue.body || '', 'Areas');

  const selectedType = resolveSingle(typeSection, typeDefs, currentTypes);
  const selectedAreas = resolveMany(areaSection, areaDefs, currentAreas);
  const valid = Boolean(selectedType) && selectedAreas.length >= (policy.rules?.areaMinimum ?? 1);

  const desiredManaged = new Set([
    ...(selectedType ? [selectedType.label] : currentTypes),
    ...selectedAreas.map((x) => x.label),
    ...(!valid ? [triageLabel] : []),
  ]);

  return {
    current,
    desired: [...current.filter((x) => !managed.has(x)), ...desiredManaged],
    needsTriage: !valid,
  };
}

async function reconcileDependencies(currentRepo, issue) {
  const blockedBy = parseReferences(readSection(issue.body || '', 'Blocked by').value, currentRepo);
  const blocking = parseReferences(readSection(issue.body || '', 'Blocking').value, currentRepo);
  if (!blockedBy.length && !blocking.length) return;

  for (const ref of blockedBy) {
    counters.dependencyLinksAttempted++;
    if (dryRun) continue;
    const blocker = await getIssueRef(ref);
    if (!blocker?.id) continue;
    await addBlockedBy(currentRepo, issue.number, blocker.id);
  }

  for (const ref of blocking) {
    counters.dependencyLinksAttempted++;
    if (dryRun) continue;
    const target = await getIssueRef(ref);
    if (!target?.id) continue;
    await addBlockedBy(ref.repo, ref.number, issue.id);
  }
}

function parseReferences(value, currentRepo) {
  if (!value || /_?no response_?/i.test(value)) return [];

  const refs = [];
  const seen = new Set();
  const tokens = value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

  for (const raw of tokens) {
    let repo = currentRepo;
    let number = null;

    const url = raw.match(/^https:\/\/github\.com\/([^/]+\/[^/]+)\/issues\/(\d+)/i);
    const qualified = raw.match(/^([^/\s]+\/[^#\s]+)#(\d+)$/);
    const local = raw.match(/^#(\d+)$/);

    if (url) {
      repo = url[1];
      number = Number(url[2]);
    } else if (qualified) {
      repo = qualified[1];
      number = Number(qualified[2]);
    } else if (local) {
      number = Number(local[1]);
    }

    if (!repo || !number) continue;
    const key = `${repo.toLowerCase()}#${number}`;
    if (seen.has(key)) continue;
    seen.add(key);
    refs.push({ repo, number });
  }

  return refs;
}

async function getIssueRef(ref) {
  try {
    const issue = await rest(`/repos/${ref.repo}/issues/${ref.number}`);
    return issue.pull_request ? null : issue;
  } catch {
    return null;
  }
}

async function addBlockedBy(repoName, issueNumber, blockerId) {
  const response = await request(`/repos/${repoName}/issues/${issueNumber}/dependencies/blocked_by`, {
    method: 'POST',
    body: { issue_id: blockerId },
  });
  if (![201, 422].includes(response.status)) {
    throw new SafeError(`Dependency request failed (${response.status}).`);
  }
}

function resolveSingle(section, defs, current) {
  if (section.present) {
    const values = parseValues(section.value);
    return defs.find((d) => values.some((v) => eq(v, d.value) || eq(v, d.label))) || null;
  }
  if (current.length === 1) return defs.find((d) => eq(d.label, current[0])) || null;
  return null;
}

function resolveMany(section, defs, current) {
  if (section.present) {
    const values = parseValues(section.value);
    return defs.filter((d) => values.some((v) => eq(v, d.value) || eq(v, d.label)));
  }
  return defs.filter((d) => current.some((x) => eq(x, d.label)));
}

function readSection(body, heading) {
  const lines = body.split(/\r?\n/);
  const target = `### ${heading}`.toLowerCase();
  const start = lines.findIndex((line) => line.trim().toLowerCase() === target);
  if (start < 0) return { present: false, value: '' };

  const out = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (/^###\s+/.test(lines[i].trim())) break;
    out.push(lines[i]);
  }
  return { present: true, value: out.join('\n').trim() };
}

function parseValues(value) {
  if (!value || /_?no response_?/i.test(value)) return [];
  return value
    .split(/[\n,]/)
    .map((v) => v.replace(/^[-*]\s+/, '').replace(/^\[[ xX]\]\s*/, '').trim())
    .filter(Boolean);
}

async function getContent(repoName, filePath, ref = '') {
  try {
    const suffix = ref ? `?ref=${encodeURIComponent(ref)}` : '';
    return await rest(`/repos/${repoName}/contents/${encodePath(filePath)}${suffix}`);
  } catch (error) {
    if (error instanceof SafeError && (error.status === 404 || error.status === 409)) return null;
    throw error;
  }
}

function decodeContent(file) {
  return Buffer.from(String(file.content || '').replace(/\n/g, ''), 'base64').toString('utf8');
}

async function putContent(repoName, filePath, content, message, sha) {
  const body = {
    message,
    content: Buffer.from(content, 'utf8').toString('base64'),
  };
  if (sha) body.sha = sha;
  await rest(`/repos/${repoName}/contents/${encodePath(filePath)}`, { method: 'PUT', body });
}

function encodePath(filePath) {
  return filePath.split('/').map(encodeURIComponent).join('/');
}

async function graphql(query, variables = {}) {
  const data = await rest('https://api.github.com/graphql', {
    method: 'POST',
    body: { query, variables },
  });
  if (Array.isArray(data?.errors) && data.errors.length > 0) {
    throw new SafeError('GitHub GraphQL mutation failed.');
  }
  return data?.data || null;
}

async function rest(urlPath, options = {}) {
  const response = await request(urlPath, options);
  if (!response.ok) {
    const error = new SafeError(`GitHub REST request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  if (response.status === 204) return null;
  return response.json();
}

async function request(urlPath, options = {}) {
  const url = urlPath.startsWith('https://') ? urlPath : `https://api.github.com${urlPath}`;
  return fetch(url, {
    method: options.method || 'GET',
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
      'x-github-api-version': '2026-03-10',
      'user-agent': 'development-hq-governance',
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
}

function safeError(prefix, error) {
  const message = error instanceof SafeError ? error.message : 'Unexpected error (details intentionally suppressed).';
  console.error(`${prefix}: ${message}`);
}
function sameSet(a, b) {
  const x = new Set(a);
  const y = new Set(b);
  return x.size === y.size && [...x].every((v) => y.has(v));
}
function normalizeLf(text) {
  return String(text ?? '').replace(/\r\n/g, '\n');
}
function readUtf8Lf(filePath) {
  return normalizeLf(fs.readFileSync(filePath, 'utf8'));
}
function eq(a, b) {
  return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}
function unique(values) {
  return [...new Set(values)];
}
function env(name, fallback = '') {
  return String(process.env[name] ?? fallback).trim();
}
function required(name) {
  const value = env(name);
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}
function boolEnv(name, fallback) {
  const value = env(name);
  return value ? ['1', 'true', 'yes', 'on'].includes(value.toLowerCase()) : fallback;
}
function intEnv(name, fallback, min, max) {
  const value = Number.parseInt(env(name, String(fallback)), 10);
  return Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : fallback;
}
function choiceEnv(name, allowed, fallback) {
  const value = env(name, fallback).toLowerCase();
  return allowed.includes(value) ? value : fallback;
}
function csvSet(name) {
  return new Set(env(name).split(',').map((x) => x.trim().toLowerCase()).filter(Boolean));
}
