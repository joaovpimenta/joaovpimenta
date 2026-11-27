import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  AGENTS_END_MARKER,
  AGENTS_START_MARKER,
  buildDependabotConfig,
  buildMainBranchRulesetPayload,
  computeQualityVariablePlan,
  detectRepoStack,
  evaluateGovernanceAutoMergeEligibility,
  isSensitivePath,
  reconcileAgentsMd,
  resolveRequiredStatusChecks,
  shouldGovernRepo,
} from './governance-policy.mjs';

const qualityDefaults = JSON.parse(fs.readFileSync('governance/quality-defaults.json', 'utf8'));
const agentsTemplate = fs.readFileSync('governance/defaults/AGENTS.md', 'utf8');

test('shouldGovernRepo ignores forks by default unless opted in via topic, and respects governance-ignore', () => {
  const baseRepo = {
    full_name: 'joaovpimenta/demo',
    archived: false,
    disabled: false,
    fork: false,
    topics: [],
    owner: { login: 'joaovpimenta', type: 'User' },
    permissions: { push: true, admin: true },
  };

  assert.equal(shouldGovernRepo(baseRepo), true);
  assert.equal(shouldGovernRepo({ ...baseRepo, fork: true }), false);
  assert.equal(shouldGovernRepo({ ...baseRepo, fork: true, topics: ['governance-managed'] }), true);
  assert.equal(shouldGovernRepo({ ...baseRepo, topics: ['governance-ignore'] }), false);
  assert.equal(shouldGovernRepo({ ...baseRepo, archived: true }), false);
});

test('detectRepoStack identifies web, java maven/gradle, android, python, and shell-static without repos.json', () => {
  const web = detectRepoStack(['package.json', 'pnpm-lock.yaml'], {
    packageJson: { scripts: { 'test:coverage': 'vitest run --coverage' } },
  });
  assert.equal(web.stack, 'web');
  assert.equal(web.packageManager, 'pnpm');
  assert.deepEqual(web.ecosystems, ['github-actions', 'npm']);
  assert.equal(web.stackVariables.QLTY_WEB_TEST_CMD, 'pnpm run test:coverage');

  const javaMaven = detectRepoStack(['pom.xml', 'src']);
  assert.equal(javaMaven.stack, 'java');
  assert.equal(javaMaven.stackVariables.QLTY_JAVA_BUILD_TOOL, 'maven');
  assert.deepEqual(javaMaven.ecosystems, ['github-actions', 'maven']);

  const android = detectRepoStack(['build.gradle.kts', 'settings.gradle.kts', 'app'], { gradleHasAndroid: true });
  assert.equal(android.stack, 'android');
  assert.deepEqual(android.ecosystems, ['github-actions', 'gradle']);

  const py = detectRepoStack(['pyproject.toml']);
  assert.equal(py.stack, 'python');
  assert.deepEqual(py.ecosystems, ['github-actions', 'pip']);

  const staticRepo = detectRepoStack(['README.md', 'index.html']);
  assert.equal(staticRepo.stack, 'shell-static');
  assert.deepEqual(staticRepo.ecosystems, ['github-actions']);
});

test('computeQualityVariablePlan always syncs platform vars and only creates missing policy vars', () => {
  const webStack = detectRepoStack(['package.json', 'pnpm-lock.yaml']);
  const plan = computeQualityVariablePlan(
    {
      QLTY_VERSION: '0.671.0',
      QLTY_POLICY_REF: 'qlty-v0.2.0',
      QLTY_MIN_COVERAGE_TOTAL: '65',
      CUSTOM_APP_VAR: 'keep-me',
    },
    webStack,
    qualityDefaults,
  );

  assert.deepEqual(
    plan.update.map((item) => item.name).sort(),
    ['QLTY_POLICY_REF', 'QLTY_VERSION'],
  );
  assert.ok(!plan.update.some((item) => item.name === 'QLTY_MIN_COVERAGE_TOTAL'), 'Must never overwrite per-repo coverage threshold');
  assert.ok(!plan.create.some((item) => item.name === 'QLTY_MIN_COVERAGE_TOTAL'));
  assert.ok(plan.create.some((item) => item.name === 'QLTY_MIN_COVERAGE_DIFF' && item.value === '90'));
  assert.ok(plan.create.some((item) => item.name === 'QLTY_MAX_CYCLOMATIC' && item.value === '10'));
  assert.ok(plan.create.some((item) => item.name === 'QLTY_WEB_PACKAGE_MANAGER' && item.value === 'pnpm'));

  const staticStack = detectRepoStack(['README.md']);
  const staticPlan = computeQualityVariablePlan({}, staticStack, qualityDefaults);
  assert.ok(staticPlan.create.some((item) => item.name === 'QLTY_COVERAGE_MODE' && item.value === 'none'));
  assert.ok(!staticPlan.create.some((item) => item.name === 'QLTY_MIN_COVERAGE_TOTAL'));
});

test('buildDependabotConfig enforces weekly limit 1 and grouped minor/patch updates', () => {
  const yaml = buildDependabotConfig({ ecosystems: ['github-actions', 'npm'] });
  assert.match(yaml, /^# managed-by: development-hq-governance/);
  assert.match(yaml, /package-ecosystem: "github-actions"/);
  assert.match(yaml, /package-ecosystem: "npm"/);
  assert.match(yaml, /interval: "weekly"/);
  assert.match(yaml, /open-pull-requests-limit: 1/);
  assert.match(yaml, /- "minor"/);
  assert.match(yaml, /- "patch"/);
  assert.ok(!yaml.includes('- "major"'));
});

test('reconcileAgentsMd creates with frontmatter, updates bounded section non-destructively, and never clobbers custom files', () => {
  const created = reconcileAgentsMd(null, agentsTemplate);
  assert.equal(created.action, 'create');
  assert.match(created.content, /managed_by: development-hq-governance/);
  assert.match(created.content, /reminder:/);

  const customWithMarkers = `---\nmanaged_by: development-hq-governance\npolicy_version: 0.9.0\n---\n\n# My Repo\n\n${AGENTS_START_MARKER}\nold text\n${AGENTS_END_MARKER}\n\n## Custom Project Notes\nKeep this intact.\n`;
  const updated = reconcileAgentsMd(customWithMarkers, agentsTemplate);
  assert.equal(updated.action, 'update');
  assert.match(updated.content, /policy_version: 1\.0\.0/);
  assert.match(updated.content, /90% de cobertura geral/);
  assert.match(updated.content, /## Custom Project Notes\nKeep this intact\./);

  const customUntagged = '# My completely custom AGENTS.md\nDo not touch.\n';
  const conflict = reconcileAgentsMd(customUntagged, agentsTemplate);
  assert.equal(conflict.action, 'conflict');
  assert.equal(conflict.content, customUntagged);
});

test('evaluateGovernanceAutoMergeEligibility enforces owner authorship, same repo, and blocks sensitive files in safe-only mode', () => {
  const repo = { full_name: 'joaovpimenta/are', owner: { login: 'joaovpimenta' }, topics: [] };
  const ownerPr = {
    draft: false,
    user: { login: 'joaovpimenta' },
    head: { repo: { full_name: 'joaovpimenta/are' } },
  };
  const ownerCommits = [{ author: { login: 'joaovpimenta' }, committer: { login: 'web-flow' } }];

  // Safe templates only -> eligible
  const ok = evaluateGovernanceAutoMergeEligibility({
    mode: 'safe-only',
    repo,
    pr: ownerPr,
    changedFiles: ['.github/ISSUE_TEMPLATE/work-item.yml', '.github/PULL_REQUEST_TEMPLATE.md', 'AGENTS.md'],
    commits: ownerCommits,
  });
  assert.equal(ok.eligible, true);

  // Workflow file changed -> blocked in safe-only
  const workflowBlocked = evaluateGovernanceAutoMergeEligibility({
    mode: 'safe-only',
    repo,
    pr: ownerPr,
    changedFiles: ['.github/workflows/governance.yml', 'AGENTS.md'],
    commits: ownerCommits,
  });
  assert.equal(workflowBlocked.eligible, false);
  assert.match(workflowBlocked.reason, /sensitive/i);

  // Sensitive config (.qlty/qlty.toml or package.json) -> blocked
  assert.equal(isSensitivePath('.qlty/qlty.toml'), true);
  assert.equal(isSensitivePath('package.json'), true);
  assert.equal(isSensitivePath('.github/dependabot.yml'), false);
  assert.equal(isSensitivePath('AGENTS.md'), false);

  // Non-owner PR author -> blocked even in 'all' mode
  const outsider = evaluateGovernanceAutoMergeEligibility({
    mode: 'all',
    repo,
    pr: { ...ownerPr, user: { login: 'someone-else' } },
    changedFiles: ['AGENTS.md'],
    commits: ownerCommits,
  });
  assert.equal(outsider.eligible, false);
  assert.match(outsider.reason, /owner/i);

  // External fork PR -> blocked
  const forkPr = evaluateGovernanceAutoMergeEligibility({
    mode: 'safe-only',
    repo,
    pr: { ...ownerPr, head: { repo: { full_name: 'outsider/are' } } },
    changedFiles: ['AGENTS.md'],
    commits: ownerCommits,
  });
  assert.equal(forkPr.eligible, false);
  assert.match(forkPr.reason, /fork/i);

  // Commit authored by non-owner inside owner PR -> blocked
  const mixedCommits = evaluateGovernanceAutoMergeEligibility({
    mode: 'safe-only',
    repo,
    pr: ownerPr,
    changedFiles: ['AGENTS.md'],
    commits: [
      { author: { login: 'joaovpimenta' }, committer: { login: 'joaovpimenta' } },
      { author: { login: 'other-dev' }, committer: { login: 'joaovpimenta' } },
    ],
  });
  assert.equal(mixedCommits.eligible, false);
  assert.match(mixedCommits.reason, /not authored by repository owner/i);

  // Opt-out topic -> blocked
  const optedOut = evaluateGovernanceAutoMergeEligibility({
    mode: 'safe-only',
    repo: { ...repo, topics: ['governance-no-automerge'] },
    pr: ownerPr,
    changedFiles: ['AGENTS.md'],
    commits: ownerCommits,
  });
  assert.equal(optedOut.eligible, false);
});

test('buildMainBranchRulesetPayload and resolveRequiredStatusChecks produce solo-friendly ruleset', () => {
  assert.deepEqual(resolveRequiredStatusChecks({ hasQltyConfig: true }), ['qlty-quality']);
  assert.deepEqual(
    resolveRequiredStatusChecks({
      hasQltyConfig: true,
      existingVars: { QLTY_REQUIRED_CHECKS: 'ci-gate, qlty-quality' },
    }),
    ['ci-gate', 'qlty-quality'],
  );
  assert.deepEqual(resolveRequiredStatusChecks({ hasQltyConfig: false }), []);

  const payload = buildMainBranchRulesetPayload({ requiredChecks: ['ci-gate', 'qlty-quality'] });
  assert.equal(payload.enforcement, 'active');
  assert.deepEqual(payload.conditions.ref_name.include, ['~DEFAULT_BRANCH']);
  assert.equal(payload.rules.length, 4);
  const prRule = payload.rules.find((r) => r.type === 'pull_request');
  assert.equal(prRule.parameters.required_approving_review_count, 0);
  const checksRule = payload.rules.find((r) => r.type === 'required_status_checks');
  assert.deepEqual(
    checksRule.parameters.required_status_checks.map((c) => c.context),
    ['ci-gate', 'qlty-quality'],
  );
});
