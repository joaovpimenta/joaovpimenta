import fs from 'node:fs';

class SafeError extends Error {}

const token = required('GH_TOKEN');
const projectOwner = env('PROJECT_OWNER', 'joaovpimenta');
const lookbackMinutes = intEnv('LOOKBACK_MINUTES', 180, 30, 10080);
const dryRun = boolEnv('DRY_RUN', false);
const retrofitHistory = boolEnv('RETROFIT_HISTORY', false);
const allowlist = csvSet('REPO_ALLOWLIST');
const denylist = csvSet('REPO_DENYLIST');
const policy = JSON.parse(fs.readFileSync('governance/taxonomy.json', 'utf8'));

process.stdout.write(`::add-mask::${token}\n`);

const counters = {
  discovered: 0,
  governed: 0,
  labelsCreated: 0,
  labelsUpdated: 0,
  callersCreated: 0,
  callersUpdated: 0,
  callerConflicts: 0,
  ownerDefaultsSynced: 0,
  ownerDefaultsMissing: 0,
  ownerDefaultsInvalid: 0,
  issuesScanned: 0,
  issuesNormalized: 0,
  needsTriage: 0,
  dependencyLinksAttempted: 0,
  errors: 0
};

try {
  const repos = await listRepos();
  counters.discovered = repos.length;

  const governed = repos.filter(isGovernedRepo);
  counters.governed = governed.length;

  for (const repo of governed) {
    try {
      await ensureLabels(repo);
      if (repo.name !== '.github') await ensureCaller(repo);
      await normalizeRecentIssues(repo);
    } catch (error) {
      counters.errors++;
      safeError('Repository governance failed', error);
    }
  }

  const owners = unique(governed.map(r => r.owner?.login).filter(Boolean));
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
  console.log(`Managed callers created: ${counters.callersCreated}`);
  console.log(`Managed callers updated: ${counters.callersUpdated}`);
  console.log(`Caller conflicts: ${counters.callerConflicts}`);
  console.log(`Owner defaults synced: ${counters.ownerDefaultsSynced}`);
  console.log(`Owner defaults missing: ${counters.ownerDefaultsMissing}`);
  console.log(`Owner defaults invalid: ${counters.ownerDefaultsInvalid}`);
  console.log(`Issues scanned: ${counters.issuesScanned}`);
  console.log(`Issues normalized: ${counters.issuesNormalized}`);
  console.log(`Needs triage: ${counters.needsTriage}`);
  console.log(`Dependency links attempted: ${counters.dependencyLinksAttempted}`);
  console.log(`Errors: ${counters.errors}`);
  console.log(`Scope: ${retrofitHistory ? 'FULL HISTORY' : `INCREMENTAL ${lookbackMinutes}m`}`);
  console.log(`Mode: ${dryRun ? 'DRY RUN' : 'APPLY'}`);
}

async function listRepos() {
  const out = [];
  for (let page = 1; page <= 100; page++) {
    const batch = await rest(`/user/repos?per_page=100&page=${page}&affiliation=owner,collaborator,organization_member&sort=updated`);
    out.push(...batch);
    if (batch.length < 100) break;
  }
  return out;
}

function isGovernedRepo(repo) {
  if (!repo || repo.archived || repo.disabled) return false;

  const full = repo.full_name.toLowerCase();
  if (denylist.has(full)) return false;
  if (allowlist.size && !allowlist.has(full)) return false;

  const ownedPersonally = repo.owner?.login?.toLowerCase() === projectOwner.toLowerCase();
  const organizationAdmin = repo.owner?.type === 'Organization' && Boolean(repo.permissions?.admin);

  return Boolean(repo.permissions?.push) && (ownedPersonally || organizationAdmin);
}

async function ensureLabels(repo) {
  const desired = [
    ...(policy.type || []),
    ...(policy.area || []),
    ...(policy.policyLabels || [])
  ];

  const current = await listLabels(repo.full_name);
  const byName = new Map(current.map(x => [x.name.toLowerCase(), x]));

  for (const def of desired) {
    const found = byName.get(def.label.toLowerCase());
    if (!found) {
      counters.labelsCreated++;
      if (!dryRun) {
        await rest(`/repos/${repo.full_name}/labels`, {
          method: 'POST',
          body: { name: def.label, color: def.color, description: def.description }
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
            description: def.description
          }
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

async function ensureCaller(repo) {
  const path = '.github/workflows/governance.yml';
  const desired = fs.readFileSync('governance/defaults/governance-caller.yml', 'utf8');
  const existing = await getContent(repo.full_name, path);

  if (!existing) {
    counters.callersCreated++;
    if (!dryRun) await putContent(repo.full_name, path, desired, 'chore: install governance workflow');
    return;
  }

  const current = decodeContent(existing);
  if (current === desired) return;

  if (!current.startsWith('# managed-by: development-hq-governance')) {
    counters.callerConflicts++;
    return;
  }

  counters.callersUpdated++;
  if (!dryRun) {
    await putContent(repo.full_name, path, desired, 'chore: update governance workflow', existing.sha);
  }
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
    ['.github/PULL_REQUEST_TEMPLATE.md', 'governance/defaults/PULL_REQUEST_TEMPLATE.md']
  ];

  let changed = false;
  for (const [target, source] of files) {
    const desired = fs.readFileSync(source, 'utf8');
    const existing = await getContent(repoName, target);
    if (existing && decodeContent(existing) === desired) continue;

    changed = true;
    if (!dryRun) {
      await putContent(
        repoName,
        target,
        desired,
        existing ? 'chore: update default governance template' : 'chore: add default governance template',
        existing?.sha
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
            body: { labels: result.desired }
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
      page: String(page)
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
    ...typeDefs.map(x => x.label),
    ...areaDefs.map(x => x.label),
    ...(policy.policyLabels || []).map(x => x.label)
  ]);

  const current = (issue.labels || []).map(x => typeof x === 'string' ? x : x.name).filter(Boolean);
  const currentTypes = current.filter(x => typeDefs.some(d => eq(d.label, x)));
  const currentAreas = current.filter(x => areaDefs.some(d => eq(d.label, x)));

  const typeSection = readSection(issue.body || '', 'Type');
  const areaSection = readSection(issue.body || '', 'Areas');

  const selectedType = resolveSingle(typeSection, typeDefs, currentTypes);
  const selectedAreas = resolveMany(areaSection, areaDefs, currentAreas);
  const valid = Boolean(selectedType) && selectedAreas.length >= (policy.rules?.areaMinimum ?? 1);

  const desiredManaged = new Set([
    ...(selectedType ? [selectedType.label] : currentTypes),
    ...selectedAreas.map(x => x.label),
    ...(!valid ? [triageLabel] : [])
  ]);

  return {
    current,
    desired: [...current.filter(x => !managed.has(x)), ...desiredManaged],
    needsTriage: !valid
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
  const tokens = value.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);

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
    allow: [201, 422]
  });
  if (![201, 422].includes(response.status)) {
    throw new SafeError(`Dependency request failed (${response.status}).`);
  }
}

function resolveSingle(section, defs, current) {
  if (section.present) {
    const values = parseValues(section.value);
    return defs.find(d => values.some(v => eq(v, d.value) || eq(v, d.label))) || null;
  }
  if (current.length === 1) return defs.find(d => eq(d.label, current[0])) || null;
  return null;
}

function resolveMany(section, defs, current) {
  if (section.present) {
    const values = parseValues(section.value);
    return defs.filter(d => values.some(v => eq(v, d.value) || eq(v, d.label)));
  }
  return defs.filter(d => current.some(x => eq(x, d.label)));
}

function readSection(body, heading) {
  const lines = body.split(/\r?\n/);
  const target = `### ${heading}`.toLowerCase();
  const start = lines.findIndex(line => line.trim().toLowerCase() === target);
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
    .map(v => v.replace(/^[-*]\s+/, '').replace(/^\[[ xX]\]\s*/, '').trim())
    .filter(Boolean);
}

async function getContent(repoName, path) {
  try {
    return await rest(`/repos/${repoName}/contents/${encodePath(path)}`);
  } catch (error) {
    if (error instanceof SafeError && error.status === 404) return null;
    throw error;
  }
}

function decodeContent(file) {
  return Buffer.from(String(file.content || '').replace(/\n/g, ''), 'base64').toString('utf8');
}

async function putContent(repoName, path, content, message, sha) {
  const body = {
    message,
    content: Buffer.from(content, 'utf8').toString('base64')
  };
  if (sha) body.sha = sha;
  await rest(`/repos/${repoName}/contents/${encodePath(path)}`, { method: 'PUT', body });
}

function encodePath(path) {
  return path.split('/').map(encodeURIComponent).join('/');
}

async function rest(path, options = {}) {
  const response = await request(path, options);
  if (!response.ok) {
    const error = new SafeError(`GitHub REST request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  if (response.status === 204) return null;
  return response.json();
}

async function request(path, options = {}) {
  const url = path.startsWith('https://') ? path : `https://api.github.com${path}`;
  return fetch(url, {
    method: options.method || 'GET',
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
      'x-github-api-version': '2026-03-10',
      'user-agent': 'development-hq-governance'
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
}

function safeError(prefix, error) {
  const message = error instanceof SafeError ? error.message : 'Unexpected error (details intentionally suppressed).';
  console.error(`${prefix}: ${message}`);
}
function sameSet(a, b) {
  const x = new Set(a);
  const y = new Set(b);
  return x.size === y.size && [...x].every(v => y.has(v));
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
  return value ? ['1','true','yes','on'].includes(value.toLowerCase()) : fallback;
}
function intEnv(name, fallback, min, max) {
  const value = Number.parseInt(env(name, String(fallback)), 10);
  return Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : fallback;
}
function csvSet(name) {
  return new Set(env(name).split(',').map(x => x.trim().toLowerCase()).filter(Boolean));
}
