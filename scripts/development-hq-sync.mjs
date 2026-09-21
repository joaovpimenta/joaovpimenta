class SafeError extends Error {}

const token = required('GH_TOKEN');
const owner = env('PROJECT_OWNER', 'joaovpimenta');
const projectNumber = intEnv('PROJECT_NUMBER', 2, 1, 1000000);
const lookbackMinutes = intEnv('LOOKBACK_MINUTES', 180, 30, 10080);
const dryRun = boolEnv('DRY_RUN', false);
const backfillOpen = boolEnv('BACKFILL_OPEN', false);
const retrofitHistory = boolEnv('RETROFIT_HISTORY', false);
const includeIssues = boolEnv('INCLUDE_ISSUES', true);
const includePrs = boolEnv('INCLUDE_PRS', true);
const minPermission = env('MIN_PERMISSION', 'push').toLowerCase();
const allowlist = csvSet('REPO_ALLOWLIST');
const denylist = csvSet('REPO_DENYLIST');
const debug = env('LOG_LEVEL', 'info').toLowerCase() === 'debug';

process.stdout.write(`::add-mask::${token}\n`);

const counters = {
  discovered: 0,
  eligible: 0,
  candidates: 0,
  alreadyPresent: 0,
  wouldAdd: 0,
  added: 0,
  filtered: 0,
  errors: 0
};
const since = new Date(Date.now() - lookbackMinutes * 60_000).toISOString();

try {
  const project = await graphql(
    `query($login:String!,$number:Int!){ user(login:$login){ projectV2(number:$number){ id } } }`,
    { login: owner, number: projectNumber }
  );
  const projectId = project.user?.projectV2?.id;
  if (!projectId) throw new SafeError('Configured Project was not found or token cannot access it.');

  const repos = await listRepos();
  counters.discovered = repos.length;
  const eligible = repos.filter(isEligible);
  counters.eligible = eligible.length;

  const projectContentIds = await listProjectContentIds(projectId);

  for (const repo of eligible) {
    const items = await listRepoItems(repo.full_name);
    for (const item of items) {
      const isPr = Boolean(item.pull_request);
      if ((isPr && !includePrs) || (!isPr && !includeIssues)) {
        counters.filtered++;
        continue;
      }

      counters.candidates++;
      const contentId = item.node_id;
      if (!contentId) {
        counters.filtered++;
        continue;
      }

      if (projectContentIds.has(contentId)) {
        counters.alreadyPresent++;
        continue;
      }

      if (dryRun) {
        counters.wouldAdd++;
        continue;
      }

      try {
        await graphql(
          `mutation($project:ID!,$content:ID!){ addProjectV2ItemById(input:{projectId:$project,contentId:$content}){ item{id} } }`,
          { project: projectId, content: contentId }
        );
        projectContentIds.add(contentId);
        counters.added++;
      } catch (error) {
        counters.errors++;
        safeError('Item sync failed', error);
      }
    }
  }
} catch (error) {
  safeError('Sync failed', error);
  process.exitCode = 1;
} finally {
  console.log('Development HQ Sync');
  console.log(`Repositories discovered: ${counters.discovered}`);
  console.log(`Repositories eligible: ${counters.eligible}`);
  console.log(`Candidate items: ${counters.candidates}`);
  console.log(`Already in Project: ${counters.alreadyPresent}`);
  console.log(`Would add: ${counters.wouldAdd}`);
  console.log(`Added: ${counters.added}`);
  console.log(`Filtered: ${counters.filtered}`);
  console.log(`Errors: ${counters.errors}`);
  console.log(`Scope: ${retrofitHistory ? 'FULL HISTORY' : backfillOpen ? 'OPEN BACKFILL' : `INCREMENTAL ${lookbackMinutes}m`}`);
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

function isEligible(repo) {
  if (repo.archived || repo.disabled) return false;
  const name = repo.full_name.toLowerCase();
  if (denylist.has(name)) return false;
  if (allowlist.size && !allowlist.has(name)) return false;
  const p = repo.permissions || {};
  const levels = { pull: 1, triage: 2, push: 3, maintain: 4, admin: 5 };
  const requiredLevel = levels[minPermission] ?? levels.push;
  const actualLevel = p.admin ? 5 : p.maintain ? 4 : p.push ? 3 : p.triage ? 2 : p.pull ? 1 : 0;
  if (actualLevel < requiredLevel) return false;

  const ownedPersonally = repo.owner?.login?.toLowerCase() === owner.toLowerCase();
  const organizationAdmin = repo.owner?.type === 'Organization' && Boolean(p.admin);
  return ownedPersonally || organizationAdmin;
}

async function listRepoItems(repoFullName) {
  const repoPath = repoFullName.split('/').map(encodeURIComponent).join('/');
  const out = [];

  for (let page = 1; page <= 100; page++) {
    const params = new URLSearchParams({
      state: retrofitHistory ? 'all' : backfillOpen ? 'open' : 'all',
      sort: 'updated',
      direction: 'desc',
      per_page: '100',
      page: String(page)
    });

    if (!retrofitHistory && !backfillOpen) params.set('since', since);

    const batch = await rest(`/repos/${repoPath}/issues?${params.toString()}`);
    out.push(...batch);
    if (batch.length < 100) break;
  }

  return out;
}

async function listProjectContentIds(projectId) {
  const ids = new Set();
  let after = null;

  for (let page = 1; page <= 500; page++) {
    const data = await graphql(
      `query($id:ID!,$after:String){
        node(id:$id){
          ... on ProjectV2 {
            items(first:100,after:$after){
              nodes {
                content {
                  __typename
                  ... on Issue { id }
                  ... on PullRequest { id }
                }
              }
              pageInfo { hasNextPage endCursor }
            }
          }
        }
      }`,
      { id: projectId, after }
    );

    const items = data.node?.items;
    if (!items) throw new SafeError('Project items could not be read.');

    for (const node of items.nodes || []) {
      const id = node.content?.id;
      if (id) ids.add(id);
    }

    if (!items.pageInfo?.hasNextPage) break;
    after = items.pageInfo.endCursor;
    if (!after) break;
  }

  return ids;
}

async function rest(path) {
  const url = path.startsWith('https://') ? path : `https://api.github.com${path}`;
  const response = await fetch(url, { headers: headers() });
  if (!response.ok) throw new SafeError(`GitHub REST request failed (${response.status}).`);
  return response.json();
}

async function graphql(query, variables) {
  const response = await fetch('https://api.github.com/graphql', {
    method: 'POST',
    headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables })
  });
  if (!response.ok) throw new SafeError(`GitHub GraphQL request failed (${response.status}).`);
  const data = await response.json();
  if (data.errors?.length) throw new SafeError('GitHub GraphQL operation was rejected.');
  return data.data;
}

function headers() {
  return {
    authorization: `Bearer ${token}`,
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2026-03-10',
    'user-agent': 'development-hq-sync'
  };
}

function safeError(prefix, error) {
  const message = error instanceof SafeError ? error.message : 'Unexpected error (details intentionally suppressed).';
  console.error(`${prefix}: ${message}`);
  if (debug) console.error('Debug logging is sanitized; raw API payloads are intentionally unavailable.');
}
function env(name, fallback = '') { return (process.env[name] ?? fallback).trim(); }
function required(name) { const v = env(name); if (!v) throw new Error(`Missing ${name}`); return v; }
function boolEnv(name, fallback) { const v = env(name); return v ? ['1','true','yes','on'].includes(v.toLowerCase()) : fallback; }
function intEnv(name, fallback, min, max) { const n = Number.parseInt(env(name, String(fallback)), 10); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback; }
function csvSet(name) { return new Set(env(name).split(',').map(x => x.trim().toLowerCase()).filter(Boolean)); }
