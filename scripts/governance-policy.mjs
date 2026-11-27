export const MANAGED_YAML_MARKER = '# managed-by: development-hq-governance';
export const MANAGED_HTML_MARKER = '<!-- managed-by: development-hq-governance -->';
export const AGENTS_START_MARKER = '<!-- development-hq:start -->';
export const AGENTS_END_MARKER = '<!-- development-hq:end -->';
export const GOVERNANCE_SYNC_BRANCH = 'chore/governance-sync';
export const MAIN_RULESET_NAME = 'development-hq-main-protection';

export const TOPIC_IGNORE = 'governance-ignore';
export const TOPIC_MANAGED = 'governance-managed';
export const TOPIC_QLTY_ENABLED = 'qlty-enabled';
export const TOPIC_NO_AUTOMERGE = 'governance-no-automerge';
export const TOPIC_NO_RULESET = 'governance-no-ruleset';

const SENSITIVE_PATH_PATTERNS = [
  /^\.github\/workflows\//i,
  /^\.github\/actions\//i,
  /^\.github\/CODEOWNERS$/i,
  /^CODEOWNERS$/i,
  /^\.qlty\//i,
  /^source\.toml$/i,
  /(?:^|\/)\.env(?:\.|$)/i,
  /(?:^|\/)(?:package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|pnpm-workspace\.yaml)$/i,
  /(?:^|\/)(?:pom\.xml|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?|gradle\.properties)$/i,
  /(?:^|\/)(?:pyproject\.toml|requirements[^/]*\.txt|poetry\.lock|uv\.lock)$/i,
  /(?:^|\/)(?:Dockerfile|docker-compose[^/]*\.ya?ml)$/i,
  /\.(?:sh|bash|zsh|ps1|bat|cmd|mjs|cjs|js|jsx|ts|tsx|py|java|kt|kts)$/i,
];

export function normalizeTopics(repo) {
  return new Set(
    (repo?.topics || [])
      .map((topic) => String(topic || '').trim().toLowerCase())
      .filter(Boolean),
  );
}

export function shouldGovernRepo(repo, options = {}) {
  if (!repo || repo.archived || repo.disabled) return false;

  const projectOwner = String(options.projectOwner || 'joaovpimenta').toLowerCase();
  const ignoreForks = options.ignoreForks !== false;
  const allowlist = options.allowlist instanceof Set ? options.allowlist : new Set();
  const denylist = options.denylist instanceof Set ? options.denylist : new Set();

  const full = String(repo.full_name || '').toLowerCase();
  if (!full) return false;
  if (denylist.has(full)) return false;
  if (allowlist.size > 0 && !allowlist.has(full)) return false;

  const topics = normalizeTopics(repo);
  if (topics.has(TOPIC_IGNORE)) return false;
  if (repo.fork && ignoreForks && !topics.has(TOPIC_MANAGED)) return false;

  const ownedPersonally = String(repo.owner?.login || '').toLowerCase() === projectOwner;
  const organizationAdmin = repo.owner?.type === 'Organization' && Boolean(repo.permissions?.admin);

  return Boolean(repo.permissions?.push) && (ownedPersonally || organizationAdmin);
}

export function detectRepoStack(rootEntries = [], extras = {}) {
  const names = new Set(
    rootEntries.map((entry) =>
      String(typeof entry === 'string' ? entry : entry?.name || '').trim().toLowerCase(),
    ),
  );

  const hasAndroidHint = Boolean(extras.isAndroid)
    || names.has('androidmanifest.xml')
    || names.has('local.properties')
    || (names.has('app') && (names.has('build.gradle') || names.has('build.gradle.kts')) && Boolean(extras.gradleHasAndroid));

  if (names.has('build.gradle') || names.has('build.gradle.kts')) {
    if (hasAndroidHint) {
      return {
        stack: 'android',
        ecosystems: ['github-actions', 'gradle'],
        stackVariables: {
          QLTY_ANDROID_JAVA_VERSION: '17',
        },
      };
    }
    return {
      stack: 'java',
      ecosystems: ['github-actions', 'gradle'],
      stackVariables: {
        QLTY_JAVA_VERSION: '21',
        QLTY_JAVA_BUILD_TOOL: 'gradle',
      },
    };
  }

  if (names.has('pom.xml')) {
    return {
      stack: 'java',
      ecosystems: ['github-actions', 'maven'],
      stackVariables: {
        QLTY_JAVA_VERSION: '21',
        QLTY_JAVA_BUILD_TOOL: 'maven',
      },
    };
  }

  if (names.has('package.json')) {
    const pkgManager = names.has('pnpm-lock.yaml')
      ? 'pnpm'
      : names.has('yarn.lock')
        ? 'yarn'
        : 'npm';

    const stackVariables = {
      QLTY_WEB_NODE_VERSION: '22',
      QLTY_WEB_PACKAGE_MANAGER: pkgManager,
    };

    const pkg = extras.packageJson && typeof extras.packageJson === 'object' ? extras.packageJson : null;
    if (pkg?.scripts?.['test:coverage']) {
      stackVariables.QLTY_WEB_TEST_CMD = `${pkgManager} run test:coverage`;
    }

    return {
      stack: 'web',
      packageManager: pkgManager,
      ecosystems: ['github-actions', 'npm'],
      stackVariables,
    };
  }

  if (names.has('pyproject.toml') || names.has('requirements.txt') || names.has('setup.py')) {
    return {
      stack: 'python',
      ecosystems: ['github-actions', 'pip'],
      stackVariables: {
        QLTY_PYTHON_VERSION: '3.12',
      },
    };
  }

  return {
    stack: 'shell-static',
    ecosystems: ['github-actions'],
    stackVariables: {},
  };
}

export function computeQualityVariablePlan(existingVarsMap = {}, stackInfo = {}, defaults = {}) {
  const existing = new Map();
  for (const [k, v] of Object.entries(existingVarsMap || {})) {
    existing.set(String(k), String(v ?? ''));
  }

  const platformVars = defaults.platform || {};
  const basePolicyVars = defaults.policy || {};
  const stackDefaultVars = (defaults.stacks && defaults.stacks[stackInfo.stack]) || {};
  const detectedStackVars = stackInfo.stackVariables || {};

  // Merged create-if-missing set: base policy + stack defaults + detected runtime specifics.
  const createIfMissing = {
    ...basePolicyVars,
    ...stackDefaultVars,
    ...detectedStackVars,
  };

  // If stack sets QLTY_COVERAGE_MODE=none (e.g. shell-static), drop coverage-only keys.
  if (createIfMissing.QLTY_COVERAGE_MODE === 'none') {
    delete createIfMissing.QLTY_MIN_COVERAGE_TOTAL;
    delete createIfMissing.QLTY_MIN_COVERAGE_DIFF;
    delete createIfMissing.QLTY_MIN_TESTS;
  }

  const create = [];
  const update = [];
  const unchanged = [];

  // 1) Platform variables: always-sync (keep version & policy ref up-to-date).
  for (const [name, rawVal] of Object.entries(platformVars)) {
    if (!name.startsWith('QLTY_')) continue;
    const value = String(rawVal ?? '').trim();
    if (!value) continue;
    if (!existing.has(name)) {
      create.push({ name, value, mode: 'always-sync' });
    } else if (existing.get(name) !== value) {
      update.push({ name, value, mode: 'always-sync' });
    } else {
      unchanged.push(name);
    }
  }

  // 2) Policy & stack variables: create-if-missing (never overwrite per-repo tuning).
  for (const [name, rawVal] of Object.entries(createIfMissing)) {
    if (!name.startsWith('QLTY_')) continue;
    if (Object.prototype.hasOwnProperty.call(platformVars, name)) continue;
    const value = String(rawVal ?? '').trim();
    if (!value) continue;
    if (!existing.has(name)) {
      create.push({ name, value, mode: 'create-if-missing' });
    } else {
      unchanged.push(name);
    }
  }

  return { create, update, unchanged };
}

export function buildDependabotConfig(stackInfo = {}) {
  const ecosystems = [...new Set(stackInfo.ecosystems || ['github-actions'])];
  if (!ecosystems.includes('github-actions')) {
    ecosystems.unshift('github-actions');
  }

  const lines = [
    MANAGED_YAML_MARKER,
    'version: 2',
    'updates:',
  ];

  for (const eco of ecosystems) {
    const areaLabel = eco === 'github-actions' ? 'area:infra' : 'area:security';
    const groupName = `${eco}-minor-patch`;
    lines.push(
      `  - package-ecosystem: "${eco}"`,
      '    directory: "/"',
      '    schedule:',
      '      interval: "weekly"',
      '      day: "monday"',
      '    open-pull-requests-limit: 1',
      '    labels:',
      '      - "type:tech-debt"',
      `      - "${areaLabel}"`,
      '    groups:',
      `      ${groupName}:`,
      '        update-types:',
      '          - "minor"',
      '          - "patch"',
    );
  }

  return `${lines.join('\n')}\n`;
}

export function parseFrontmatter(content) {
  const text = String(content || '');
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!match) return { hasFrontmatter: false, fields: {}, rawBlock: '', body: text };

  const fields = {};
  for (const line of match[1].split(/\r?\n/)) {
    const kv = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!kv) continue;
    fields[kv[1].trim().toLowerCase()] = kv[2].trim().replace(/^["']|["']$/g, '');
  }

  return {
    hasFrontmatter: true,
    fields,
    rawBlock: match[0],
    body: text.slice(match[0].length),
  };
}

export function reconcileAgentsMd(existingContent, templateContent) {
  const template = String(templateContent || '');
  if (existingContent === null || existingContent === undefined) {
    return { action: 'create', content: template };
  }

  const existing = String(existingContent);
  if (existing === template) {
    return { action: 'unchanged', content: existing };
  }

  const tplStart = template.indexOf(AGENTS_START_MARKER);
  const tplEnd = template.indexOf(AGENTS_END_MARKER);
  const managedSection = tplStart >= 0 && tplEnd > tplStart
    ? template.slice(tplStart, tplEnd + AGENTS_END_MARKER.length)
    : null;

  const exStart = existing.indexOf(AGENTS_START_MARKER);
  const exEnd = existing.indexOf(AGENTS_END_MARKER);

  const tplFm = parseFrontmatter(template);
  const exFm = parseFrontmatter(existing);
  const fmManaged = exFm.hasFrontmatter && exFm.fields.managed_by === 'development-hq-governance';

  // Case 1: Existing file has explicit start/end delimiters — replace only inside delimiters
  // (and refresh managed frontmatter if owned by development-hq-governance), preserving all custom content.
  if (managedSection && exStart >= 0 && exEnd > exStart) {
    let updated = existing.slice(0, exStart) + managedSection + existing.slice(exEnd + AGENTS_END_MARKER.length);
    if (fmManaged && tplFm.hasFrontmatter) {
      const updatedFm = parseFrontmatter(updated);
      updated = `${tplFm.rawBlock}${updatedFm.body}`;
    }
    return updated === existing
      ? { action: 'unchanged', content: existing }
      : { action: 'update', content: updated };
  }

  // Case 2: Whole file is explicitly marked as managed via YAML frontmatter (no custom markers).
  if (fmManaged) {
    return { action: 'update', content: template };
  }

  // Case 3: Custom repository AGENTS.md without governance markers — never overwrite.
  return { action: 'conflict', content: existing };
}

export function isSensitivePath(filePath) {
  const normalized = String(filePath || '').trim().replace(/\\/g, '/').replace(/^\/+/, '');
  if (!normalized) return true;
  return SENSITIVE_PATH_PATTERNS.some((re) => re.test(normalized));
}

export function evaluateGovernanceAutoMergeEligibility({
  mode = 'safe-only',
  repo = {},
  pr = {},
  changedFiles = [],
  commits = [],
} = {}) {
  const normalizedMode = String(mode || 'off').trim().toLowerCase();
  if (normalizedMode === 'off') {
    return { eligible: false, reason: 'auto-merge disabled (mode=off)' };
  }
  if (normalizedMode !== 'safe-only' && normalizedMode !== 'all') {
    return { eligible: false, reason: `invalid auto-merge mode (${normalizedMode})` };
  }

  const topics = normalizeTopics(repo);
  if (topics.has(TOPIC_NO_AUTOMERGE)) {
    return { eligible: false, reason: `repository opted out via topic ${TOPIC_NO_AUTOMERGE}` };
  }

  if (pr.draft) {
    return { eligible: false, reason: 'pull request is draft' };
  }

  const ownerLogin = String(repo.owner?.login || '').trim().toLowerCase();
  const repoFullName = String(repo.full_name || '').trim().toLowerCase();
  const headRepoFullName = String(pr.head?.repo?.full_name || '').trim().toLowerCase();
  const prAuthor = String(pr.user?.login || '').trim().toLowerCase();

  if (!ownerLogin || !repoFullName) {
    return { eligible: false, reason: 'missing repository owner metadata' };
  }
  if (headRepoFullName !== repoFullName) {
    return { eligible: false, reason: 'pull request originates from an external fork' };
  }
  if (prAuthor !== ownerLogin) {
    return { eligible: false, reason: 'pull request author is not repository owner' };
  }

  if (!Array.isArray(commits) || commits.length === 0) {
    return { eligible: false, reason: 'pull request commit authorship could not be verified' };
  }

  for (const commit of commits) {
    const authorLogin = String(commit?.author?.login || '').trim().toLowerCase();
    const committerLogin = String(commit?.committer?.login || '').trim().toLowerCase();
    if (authorLogin !== ownerLogin) {
      return { eligible: false, reason: 'pull request contains commit not authored by repository owner' };
    }
    if (committerLogin && committerLogin !== ownerLogin && committerLogin !== 'web-flow') {
      return { eligible: false, reason: 'pull request contains commit with non-owner committer' };
    }
  }

  if (!Array.isArray(changedFiles) || changedFiles.length === 0) {
    return { eligible: false, reason: 'no changed files detected' };
  }

  if (normalizedMode === 'safe-only') {
    const sensitive = changedFiles.filter((filePath) => isSensitivePath(filePath));
    if (sensitive.length > 0) {
      return {
        eligible: false,
        reason: `sensitive file(s) changed (${sensitive.length}) — manual review required`,
      };
    }
  }

  return { eligible: true, reason: `eligible (${normalizedMode}, owner-authored, non-sensitive)` };
}

export function resolveRequiredStatusChecks({ hasQltyConfig = false, existingVars = {} } = {}) {
  const custom = String(existingVars.QLTY_REQUIRED_CHECKS ?? '').trim();
  if (custom) {
    if (custom.toLowerCase() === 'none') return [];
    return [...new Set(custom.split(',').map((s) => s.trim()).filter(Boolean))];
  }
  if (hasQltyConfig) {
    return ['qlty-quality'];
  }
  return [];
}

export function buildMainBranchRulesetPayload({
  name = MAIN_RULESET_NAME,
  requiredChecks = [],
} = {}) {
  const rules = [
    { type: 'deletion' },
    { type: 'non_fast_forward' },
    {
      type: 'pull_request',
      parameters: {
        required_approving_review_count: 0,
        dismiss_stale_reviews_on_push: false,
        require_code_owner_review: false,
        require_last_push_approval: false,
        required_review_thread_resolution: false,
      },
    },
  ];

  if (Array.isArray(requiredChecks) && requiredChecks.length > 0) {
    rules.push({
      type: 'required_status_checks',
      parameters: {
        strict_required_status_checks_policy: false,
        do_not_enforce_on_create: false,
        required_status_checks: requiredChecks.map((context) => ({ context })),
      },
    });
  }

  return {
    name,
    target: 'branch',
    enforcement: 'active',
    conditions: {
      ref_name: {
        include: ['~DEFAULT_BRANCH'],
        exclude: [],
      },
    },
    rules,
  };
}
