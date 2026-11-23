import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const SECRET_PLUGINS = new Set(['gitleaks', 'trufflehog']);
const ALWAYS_ADVISORY_PLUGINS = new Set(['ripgrep']);
const DEFAULT_SMELL_BLOCK_RULES = new Set([
  'qlty:function-complexity',
  'qlty:nested-control-flow',
  'qlty:identical-code',
  'qlty:similar-code',
  'qlty:boolean-logic',
  'qlty:function-parameters',
  'qlty:return-statements',
  'qlty:file-complexity',
]);

const SECRET_PATTERNS = [
  {
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    replacement: '[REDACTED]',
  },
  {
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g,
    replacement: '[REDACTED]',
  },
  {
    pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    replacement: '[REDACTED]',
  },
  {
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    replacement: '[REDACTED]',
  },
  {
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    replacement: '[REDACTED]',
  },
  {
    pattern: /\bBearer\s+[A-Za-z0-9._~+/-]{12,}=*\b/gi,
    replacement: 'Bearer [REDACTED]',
  },
  {
    pattern: /((?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*["']?)[^\s"',;]{6,}(["']?)/gi,
    replacement: '$1[REDACTED]$2',
  },
];

export function redactText(input) {
  if (!input) return '';
  let text = String(input);
  for (const { pattern, replacement } of SECRET_PATTERNS) {
    text = text.replace(pattern, replacement);
  }
  return text;
}

export function stripBomAndDecode(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    return String(buffer ?? '').replace(/^\uFEFF/, '');
  }
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) {
    return buffer.subarray(2).toString('utf16le');
  }
  if (buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
    return buffer.subarray(3).toString('utf8');
  }
  return buffer.toString('utf8');
}

export function parseSarif(rawContent, label = 'SARIF') {
  const text = stripBomAndDecode(rawContent).trim();
  if (!text) {
    throw new Error(`${label} report is empty.`);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} report is not valid JSON: ${error.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.runs)) {
    throw new Error(`${label} report is missing a valid "runs" array.`);
  }

  const findings = [];
  for (const run of parsed.runs) {
    const driverName = String(run?.tool?.driver?.name || 'unknown').toLowerCase();
    for (const result of run?.results || []) {
      const ruleId = String(result?.ruleId || 'unknown');
      const [prefix] = ruleId.includes(':') ? ruleId.split(':', 2) : [driverName];
      const plugin = prefix.toLowerCase();
      const level = normalizeLevel(result?.level);
      const categories = (result?.taxa || [])
        .map((taxon) => String(taxon?.id || '').toLowerCase())
        .filter(Boolean);
      const location = result?.locations?.[0]?.physicalLocation;
      const file = String(location?.artifactLocation?.uri || '');
      const line = Number.isInteger(location?.region?.startLine) ? location.region.startLine : null;
      const isSecret = isSecretFinding(plugin, ruleId, categories);
      const rawMessage = String(result?.message?.text || '');
      const message = isSecret
        ? '[REDACTED secret finding — inspect locally; raw secret value suppressed]'
        : redactText(rawMessage).replace(/\s+/g, ' ').trim();

      findings.push({
        plugin,
        ruleId,
        level,
        categories,
        file,
        line,
        message,
        isSecret,
      });
    }
  }

  return findings;
}

export function sanitizeSarif(rawContent) {
  const text = stripBomAndDecode(rawContent).trim();
  if (!text) return null;
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.runs)) return null;

  for (const run of parsed.runs) {
    const driverName = String(run?.tool?.driver?.name || 'unknown').toLowerCase();
    for (const result of run?.results || []) {
      const ruleId = String(result?.ruleId || 'unknown');
      const [prefix] = ruleId.includes(':') ? ruleId.split(':', 2) : [driverName];
      const plugin = prefix.toLowerCase();
      const categories = (result?.taxa || [])
        .map((taxon) => String(taxon?.id || '').toLowerCase())
        .filter(Boolean);
      const isSecret = isSecretFinding(plugin, ruleId, categories);

      if (result.message && typeof result.message.text === 'string') {
        result.message.text = isSecret
          ? '[REDACTED secret finding — inspect locally; raw secret value suppressed]'
          : redactText(result.message.text);
      }

      for (const loc of result.locations || []) {
        const region = loc?.physicalLocation?.region;
        if (region && region.snippet) {
          delete region.snippet;
        }
      }
      if (result.partialFingerprints && isSecret) {
        delete result.partialFingerprints;
      }
    }
  }
  return `${JSON.stringify(parsed, null, 2)}\n`;
}

function normalizeLevel(level) {
  const value = String(level || 'warning').toLowerCase();
  if (value === 'error' || value === 'warning' || value === 'note') return value;
  return 'warning';
}

function isSecretFinding(plugin, ruleId, categories) {
  if (SECRET_PLUGINS.has(plugin)) return true;
  if (categories.includes('secret')) return true;
  if (plugin === 'trivy' && /secret/i.test(ruleId)) return true;
  return false;
}

export function parseMetricsOutput(rawText, topN = 10) {
  const text = stripBomAndDecode(rawText || '');
  const lines = text.split(/\r?\n/);
  const functions = [];
  let currentFile = null;
  let inFunctionTable = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) {
      inFunctionTable = false;
      continue;
    }

    if (/^function\s*\|\s*fields\s*\|\s*cyclo\s*\|\s*cognitive\s*\|\s*lines\s*\|\s*loc$/i.test(line)) {
      inFunctionTable = true;
      continue;
    }
    if (/^-+\+-+/.test(line)) {
      continue;
    }

    if (inFunctionTable && line.includes('|')) {
      const parts = line.split('|').map((part) => part.trim());
      if (parts.length >= 6) {
        const cyclo = Number.parseInt(parts[2], 10);
        const cognitive = Number.parseInt(parts[3], 10);
        const totalLines = Number.parseInt(parts[4], 10);
        const loc = Number.parseInt(parts[5], 10);
        if (Number.isFinite(cyclo) && Number.isFinite(cognitive)) {
          functions.push({
            file: currentFile || '(unknown)',
            name: parts[0],
            cyclo,
            cognitive,
            lines: Number.isFinite(totalLines) ? totalLines : 0,
            loc: Number.isFinite(loc) ? loc : 0,
          });
        }
      }
      continue;
    }

    if (!line.includes('|') && !line.startsWith('[') && !line.startsWith('Computing')) {
      currentFile = line;
      inFunctionTable = false;
    }
  }

  functions.sort((a, b) => (b.cognitive - a.cognitive) || (b.cyclo - a.cyclo) || (b.loc - a.loc));
  return {
    totalFunctions: functions.length,
    overCyclo10: functions.filter((fn) => fn.cyclo > 10).length,
    overCognitive15: functions.filter((fn) => fn.cognitive > 15).length,
    topHotspots: functions.slice(0, topN),
  };
}

export function classifyFinding(finding, options = {}) {
  const enforcement = options.enforcement || 'standard';
  const advisoryPlugins = options.advisoryPlugins || new Set();
  const blockSmells = Boolean(options.blockSmells);

  if (enforcement === 'report-only') {
    return { blocking: false, reason: 'report-only mode' };
  }

  if (finding.isSecret) {
    return { blocking: true, reason: 'exposed secret finding' };
  }

  if (advisoryPlugins.has(finding.plugin) || ALWAYS_ADVISORY_PLUGINS.has(finding.plugin)) {
    return { blocking: false, reason: `advisory plugin (${finding.plugin})` };
  }

  if (finding.plugin === 'qlty') {
    const shouldBlockSmell = (blockSmells || enforcement === 'strict') && DEFAULT_SMELL_BLOCK_RULES.has(finding.ruleId);
    return {
      blocking: shouldBlockSmell,
      reason: shouldBlockSmell ? 'maintainability smell gate' : 'advisory maintainability smell',
    };
  }

  if (finding.level === 'error') {
    return { blocking: true, reason: 'high-confidence error finding' };
  }

  if (enforcement === 'strict' && finding.level === 'warning') {
    return { blocking: true, reason: 'strict mode warning finding' };
  }

  return { blocking: false, reason: `non-blocking ${finding.level} finding` };
}

export function evaluateQualityGate(input) {
  const scope = input.scope || 'pr';
  const enforcement = input.enforcement || 'standard';
  const advisoryPlugins = new Set(
    (input.advisoryPlugins || []).map((item) => String(item).trim().toLowerCase()).filter(Boolean),
  );
  const blockSmells = Boolean(input.blockSmells);

  const systemErrors = [];

  if (input.configValidateExit !== undefined && input.configValidateExit !== 0) {
    systemErrors.push(`qlty config validate failed with exit code ${input.configValidateExit}.`);
  }

  if (input.checkExit === undefined || ![0, 1].includes(input.checkExit)) {
    systemErrors.push(`qlty check failed to complete cleanly (exit code ${input.checkExit ?? 'missing'}).`);
  }

  let checkFindings = [];
  if (input.checkSarifRaw !== undefined) {
    try {
      checkFindings = parseSarif(input.checkSarifRaw, 'qlty check SARIF');
    } catch (error) {
      systemErrors.push(error.message);
    }
  } else {
    systemErrors.push('qlty check SARIF report was not provided.');
  }

  let smellFindings = [];
  if (input.smellsEnabled) {
    if (input.smellsExit === undefined || ![0, 1].includes(input.smellsExit)) {
      systemErrors.push(`qlty smells failed to complete cleanly (exit code ${input.smellsExit ?? 'missing'}).`);
    }
    if (input.smellsSarifRaw !== undefined) {
      try {
        smellFindings = parseSarif(input.smellsSarifRaw, 'qlty smells SARIF');
      } catch (error) {
        systemErrors.push(error.message);
      }
    } else {
      systemErrors.push('qlty smells SARIF report was not provided.');
    }
  }

  let metrics = null;
  if (input.metricsEnabled) {
    if (input.metricsExit !== 0) {
      systemErrors.push(`qlty metrics failed with exit code ${input.metricsExit ?? 'missing'}.`);
    } else {
      metrics = parseMetricsOutput(input.metricsRaw || '', 10);
    }
  }

  const allFindings = [...checkFindings, ...smellFindings].map((finding) => ({
    ...finding,
    gate: classifyFinding(finding, { enforcement, advisoryPlugins, blockSmells }),
  }));

  const blockingFindings = allFindings.filter((item) => item.gate.blocking);
  const advisoryFindings = allFindings.filter((item) => !item.gate.blocking);

  const byPlugin = {};
  const byLevel = { error: 0, warning: 0, note: 0 };
  for (const item of allFindings) {
    byPlugin[item.plugin] = byPlugin[item.plugin] || { total: 0, blocking: 0, advisory: 0 };
    byPlugin[item.plugin].total++;
    if (item.gate.blocking) byPlugin[item.plugin].blocking++;
    else byPlugin[item.plugin].advisory++;
    byLevel[item.level] = (byLevel[item.level] || 0) + 1;
  }

  const passed = systemErrors.length === 0 && blockingFindings.length === 0;
  const outcome = systemErrors.length > 0
    ? 'ERROR'
    : blockingFindings.length > 0
      ? 'FAIL'
      : 'PASS';

  return {
    passed,
    outcome,
    scope,
    enforcement,
    qltyVersion: input.qltyVersion || 'unknown',
    baseRef: input.baseRef || null,
    checks: {
      configValidate: input.configValidateExit === 0 ? 'pass' : 'fail',
      check: [0, 1].includes(input.checkExit) ? 'ran' : 'error',
      smells: input.smellsEnabled ? ([0, 1].includes(input.smellsExit) ? 'ran' : 'error') : 'skipped',
      metrics: input.metricsEnabled ? (input.metricsExit === 0 ? 'ran' : 'error') : 'skipped',
    },
    counts: {
      total: allFindings.length,
      blocking: blockingFindings.length,
      advisory: advisoryFindings.length,
      secrets: allFindings.filter((item) => item.isSecret).length,
      byLevel,
      byPlugin,
    },
    systemErrors,
    blockingFindings,
    advisoryFindings,
    metrics,
  };
}

export function formatMarkdownSummary(report) {
  const lines = [];
  const badge = report.outcome === 'PASS' ? 'PASS' : report.outcome === 'ERROR' ? 'ERROR (fail-closed)' : 'FAIL';
  lines.push(`## Qlty Code Quality Gate — ${badge}`);
  lines.push('');
  lines.push(`- **Scope:** \`${report.scope}\`${report.baseRef ? ` (base \`${report.baseRef}\`)` : ''}`);
  lines.push(`- **Enforcement:** \`${report.enforcement}\``);
  lines.push(`- **Qlty CLI:** \`${report.qltyVersion}\``);
  lines.push(
    `- **Stages:** config=\`${report.checks.configValidate}\`, check=\`${report.checks.check}\`, smells=\`${report.checks.smells}\`, metrics=\`${report.checks.metrics}\``,
  );
  lines.push(
    `- **Findings:** ${report.counts.total} total (${report.counts.blocking} blocking, ${report.counts.advisory} advisory, ${report.counts.secrets} secret)`,
  );
  lines.push('');

  if (report.systemErrors.length > 0) {
    lines.push('### System / Tool Errors (Fail-Closed)');
    lines.push('');
    for (const err of report.systemErrors) {
      lines.push(`- ${redactText(err)}`);
    }
    lines.push('');
  }

  const pluginEntries = Object.entries(report.counts.byPlugin).sort((a, b) => b[1].total - a[1].total);
  if (pluginEntries.length > 0) {
    lines.push('### Findings by Analyzer');
    lines.push('');
    lines.push('| Analyzer | Total | Blocking | Advisory |');
    lines.push('|---|---:|---:|---:|');
    for (const [plugin, stats] of pluginEntries) {
      lines.push(`| \`${plugin}\` | ${stats.total} | ${stats.blocking} | ${stats.advisory} |`);
    }
    lines.push('');
  }

  if (report.blockingFindings.length > 0) {
    lines.push('### Blocking Findings');
    lines.push('');
    lines.push('| Location | Rule | Level | Message |');
    lines.push('|---|---|---|---|');
    for (const item of report.blockingFindings.slice(0, 25)) {
      const loc = item.file ? `${item.file}${item.line ? `:${item.line}` : ''}` : '-';
      lines.push(`| \`${escapeMd(loc)}\` | \`${escapeMd(item.ruleId)}\` | ${item.level} | ${escapeMd(item.message)} |`);
    }
    if (report.blockingFindings.length > 25) {
      lines.push('');
      lines.push(`_Showing first 25 of ${report.blockingFindings.length} blocking findings. Inspect the uploaded SARIF artifact for the complete list._`);
    }
    lines.push('');
  }

  if (report.advisoryFindings.length > 0) {
    lines.push('### Advisory Findings (Top 15)');
    lines.push('');
    lines.push('| Location | Rule | Level | Message |');
    lines.push('|---|---|---|---|');
    for (const item of report.advisoryFindings.slice(0, 15)) {
      const loc = item.file ? `${item.file}${item.line ? `:${item.line}` : ''}` : '-';
      lines.push(`| \`${escapeMd(loc)}\` | \`${escapeMd(item.ruleId)}\` | ${item.level} | ${escapeMd(item.message)} |`);
    }
    if (report.advisoryFindings.length > 15) {
      lines.push('');
      lines.push(`_Showing first 15 of ${report.advisoryFindings.length} advisory findings._`);
    }
    lines.push('');
  }

  if (report.metrics && report.metrics.topHotspots.length > 0) {
    lines.push('### Complexity Hotspots');
    lines.push('');
    lines.push(
      `Analyzed **${report.metrics.totalFunctions}** functions — **${report.metrics.overCyclo10}** with cyclomatic > 10, **${report.metrics.overCognitive15}** with cognitive > 15.`,
    );
    lines.push('');
    lines.push('| File | Function | Cyclomatic | Cognitive | LOC |');
    lines.push('|---|---|---:|---:|---:|');
    for (const fn of report.metrics.topHotspots) {
      lines.push(`| \`${escapeMd(fn.file)}\` | \`${escapeMd(fn.name)}\` | ${fn.cyclo} | ${fn.cognitive} | ${fn.loc} |`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

const VALID_SCOPES = new Set(['pr', 'full']);
const VALID_ENFORCEMENTS = new Set(['report-only', 'standard', 'strict']);
const VALID_BOOLEANS = new Set(['true', 'false']);
const SEMVER_RE = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const POLICY_REF_RE = /^[A-Za-z0-9._/-]+$/;
const ADVISORY_PLUGINS_RE = /^[A-Za-z0-9_,-]+$/;

export const REQUIRED_PROJECT_VARS = [
  { name: 'QLTY_SCOPE', accepted: '`pr` ou `full`', example: 'pr' },
  { name: 'QLTY_ENFORCEMENT', accepted: '`report-only`, `standard` ou `strict`', example: 'standard' },
  { name: 'QLTY_VERSION', accepted: 'SemVer sem `v`', example: '0.672.0' },
  { name: 'QLTY_POLICY_REF', accepted: 'Tag ou SHA em `joaovpimenta/joaovpimenta`', example: 'qlty-v0.2.0' },
  { name: 'QLTY_ENABLE_SMELLS', accepted: '`true` ou `false`', example: 'true' },
  { name: 'QLTY_ENABLE_METRICS', accepted: '`true` ou `false`', example: 'true' },
];

export function validateProjectVariables(varsMap = {}, overrides = {}) {
  const read = (key) => String(varsMap[key] ?? '').trim();
  const problems = [];

  const scope = read('QLTY_SCOPE');
  if (!scope) {
    problems.push('Variável obrigatória ausente: `QLTY_SCOPE` (esperado: `pr` ou `full`).');
  } else if (!VALID_SCOPES.has(scope)) {
    problems.push(`Valor inválido em \`QLTY_SCOPE\`: \`${scope}\` (esperado: \`pr\` ou \`full\`).`);
  }

  const enforcement = read('QLTY_ENFORCEMENT');
  if (!enforcement) {
    problems.push('Variável obrigatória ausente: `QLTY_ENFORCEMENT` (esperado: `report-only`, `standard` ou `strict`).');
  } else if (!VALID_ENFORCEMENTS.has(enforcement)) {
    problems.push(
      `Valor inválido em \`QLTY_ENFORCEMENT\`: \`${enforcement}\` (esperado: \`report-only\`, \`standard\` ou \`strict\`).`,
    );
  }

  const qltyVersion = read('QLTY_VERSION');
  if (!qltyVersion) {
    problems.push('Variável obrigatória ausente: `QLTY_VERSION` (esperado: versão SemVer sem `v`, ex.: `0.672.0`).');
  } else if (!SEMVER_RE.test(qltyVersion)) {
    problems.push(`Valor inválido em \`QLTY_VERSION\`: \`${qltyVersion}\` (esperado: \`X.Y.Z\`, ex.: \`0.672.0\`).`);
  }

  const policyRef = read('QLTY_POLICY_REF');
  if (!policyRef) {
    problems.push('Variável obrigatória ausente: `QLTY_POLICY_REF` (esperado: tag ou SHA, ex.: `qlty-v0.2.0`).');
  } else if (!POLICY_REF_RE.test(policyRef)) {
    problems.push(`Valor inválido em \`QLTY_POLICY_REF\`: \`${policyRef}\`.`);
  }

  const enableSmells = read('QLTY_ENABLE_SMELLS');
  if (!enableSmells) {
    problems.push('Variável obrigatória ausente: `QLTY_ENABLE_SMELLS` (esperado: `true` ou `false`).');
  } else if (!VALID_BOOLEANS.has(enableSmells)) {
    problems.push(`Valor inválido em \`QLTY_ENABLE_SMELLS\`: \`${enableSmells}\` (esperado: \`true\` ou \`false\`).`);
  }

  const enableMetrics = read('QLTY_ENABLE_METRICS');
  if (!enableMetrics) {
    problems.push('Variável obrigatória ausente: `QLTY_ENABLE_METRICS` (esperado: `true` ou `false`).');
  } else if (!VALID_BOOLEANS.has(enableMetrics)) {
    problems.push(`Valor inválido em \`QLTY_ENABLE_METRICS\`: \`${enableMetrics}\` (esperado: \`true\` ou \`false\`).`);
  }

  const rawBlockSmells = read('QLTY_BLOCK_SMELLS');
  const blockSmells = rawBlockSmells || 'false';
  if (rawBlockSmells && !VALID_BOOLEANS.has(rawBlockSmells)) {
    problems.push(`Valor inválido em \`QLTY_BLOCK_SMELLS\`: \`${rawBlockSmells}\` (esperado: \`true\` ou \`false\`).`);
  }

  const rawRetention = read('QLTY_ARTIFACT_RETENTION_DAYS');
  let artifactRetentionDays = 7;
  if (rawRetention) {
    if (!/^[0-9]+$/.test(rawRetention) || Number(rawRetention) < 1 || Number(rawRetention) > 90) {
      problems.push(
        `Valor inválido em \`QLTY_ARTIFACT_RETENTION_DAYS\`: \`${rawRetention}\` (esperado: inteiro entre \`1\` e \`90\`).`,
      );
    } else {
      artifactRetentionDays = Number(rawRetention);
    }
  }

  const advisoryPlugins = read('QLTY_ADVISORY_PLUGINS').replace(/\s+/g, '');
  if (advisoryPlugins && !ADVISORY_PLUGINS_RE.test(advisoryPlugins)) {
    problems.push(`Valor inválido em \`QLTY_ADVISORY_PLUGINS\`: \`${advisoryPlugins}\` (esperado: lista CSV de plugins).`);
  }

  const scopeOverride = String(overrides.scopeOverride ?? '').trim();
  if (scopeOverride && !VALID_SCOPES.has(scopeOverride)) {
    problems.push(`Valor inválido em \`scope_override\`: \`${scopeOverride}\` (esperado: \`pr\` ou \`full\`).`);
  }

  const enforcementOverride = String(overrides.enforcementOverride ?? '').trim();
  if (enforcementOverride && !VALID_ENFORCEMENTS.has(enforcementOverride)) {
    problems.push(
      `Valor inválido em \`enforcement_override\`: \`${enforcementOverride}\` (esperado: \`report-only\`, \`standard\` ou \`strict\`).`,
    );
  }

  const valid = problems.length === 0;
  return {
    valid,
    justification: valid
      ? null
      : 'A esteira precisa ser corrigida: variáveis de ambiente obrigatórias do Qlty estão ausentes ou inválidas neste repositório.',
    problems,
    config: valid
      ? {
          scope: scopeOverride || scope,
          enforcement: enforcementOverride || enforcement,
          qltyVersion,
          policyRef,
          enableSmells: enableSmells === 'true',
          enableMetrics: enableMetrics === 'true',
          blockSmells: blockSmells === 'true',
          advisoryPlugins,
          artifactRetentionDays,
        }
      : null,
  };
}

export function formatConfigErrorSummary(validation) {
  const lines = [
    '## Qlty Code Quality Gate — ERRO DE CONFIGURAÇÃO (A esteira precisa ser corrigida)',
    '',
    validation.justification,
    '',
    'Configure as variáveis em **Settings → Secrets and variables → Actions → Variables** (ou via `gh variable set`).',
    '',
    '### Problemas encontrados',
    '',
    ...validation.problems.map((problem) => `- ${problem}`),
    '',
    '### Variáveis obrigatórias do projeto',
    '',
    '| Variável | Valores aceitos | Exemplo |',
    '|---|---|---|',
    ...REQUIRED_PROJECT_VARS.map((item) => `| \`${item.name}\` | ${item.accepted} | \`${item.example}\` |`),
    '',
  ];
  return lines.join('\n');
}

function escapeMd(value) {
  return String(value || '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function readOptionalFile(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return undefined;
  return fs.readFileSync(filePath);
}

function intEnv(name, fallback = undefined) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function requiredChoiceEnv(name, allowed, errors) {
  const value = String(process.env[name] ?? '').trim();
  if (!value) {
    errors.push(`Variável obrigatória ausente na execução do gate: \`${name}\`.`);
    return '';
  }
  if (allowed && !allowed.has(value)) {
    errors.push(`Valor inválido em \`${name}\`: \`${value}\`.`);
  }
  return value;
}

function runCli() {
  const envErrors = [];
  const scope = requiredChoiceEnv('QUALITY_SCOPE', VALID_SCOPES, envErrors);
  const enforcement = requiredChoiceEnv('QUALITY_ENFORCEMENT', VALID_ENFORCEMENTS, envErrors);
  const qltyVersion = requiredChoiceEnv('QUALITY_QLTY_VERSION', null, envErrors);
  const smellsEnabledRaw = requiredChoiceEnv('QUALITY_SMELLS_ENABLED', VALID_BOOLEANS, envErrors);
  const metricsEnabledRaw = requiredChoiceEnv('QUALITY_METRICS_ENABLED', VALID_BOOLEANS, envErrors);
  const blockSmellsRaw = String(process.env.QUALITY_BLOCK_SMELLS ?? 'false').trim();
  if (!VALID_BOOLEANS.has(blockSmellsRaw)) {
    envErrors.push(`Valor inválido em \`QUALITY_BLOCK_SMELLS\`: \`${blockSmellsRaw}\`.`);
  }

  if (envErrors.length > 0) {
    const justification =
      'A esteira precisa ser corrigida: variáveis de ambiente obrigatórias do Qlty estão ausentes ou inválidas.';
    console.error(`::error title=Esteira precisa ser corrigida::${justification}`);
    for (const err of envErrors) {
      console.error(`::error title=Variável obrigatória ausente ou inválida::${err}`);
    }
    const summaryPath = process.env.QUALITY_SUMMARY_PATH || process.env.GITHUB_STEP_SUMMARY;
    if (summaryPath) {
      fs.appendFileSync(
        summaryPath,
        `${formatConfigErrorSummary({ valid: false, justification, problems: envErrors })}\n`,
        'utf8',
      );
    }
    process.exitCode = 1;
    return;
  }

  const checkSarifRaw = readOptionalFile(process.env.QUALITY_CHECK_SARIF);
  const smellsSarifRaw = readOptionalFile(process.env.QUALITY_SMELLS_SARIF);
  const report = evaluateQualityGate({
    scope,
    enforcement,
    qltyVersion,
    baseRef: process.env.QUALITY_BASE_REF || null,
    advisoryPlugins: (process.env.QUALITY_ADVISORY_PLUGINS || '').split(','),
    blockSmells: blockSmellsRaw === 'true',
    configValidateExit: intEnv('QUALITY_CONFIG_VALIDATE_EXIT', 0),
    checkExit: intEnv('QUALITY_CHECK_EXIT'),
    checkSarifRaw,
    smellsEnabled: smellsEnabledRaw === 'true',
    smellsExit: intEnv('QUALITY_SMELLS_EXIT'),
    smellsSarifRaw,
    metricsEnabled: metricsEnabledRaw === 'true',
    metricsExit: intEnv('QUALITY_METRICS_EXIT', 0),
    metricsRaw: readOptionalFile(process.env.QUALITY_METRICS_FILE),
  });

  const markdown = formatMarkdownSummary(report);
  const summaryPath = process.env.QUALITY_SUMMARY_PATH || process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    fs.appendFileSync(summaryPath, `${markdown}\n`, 'utf8');
  }

  const reportPath = process.env.QUALITY_REPORT_PATH;
  if (reportPath) {
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  }

  const sanitizedCheckPath = process.env.QUALITY_SANITIZED_CHECK_SARIF;
  if (sanitizedCheckPath && checkSarifRaw) {
    const clean = sanitizeSarif(checkSarifRaw);
    if (clean) {
      fs.mkdirSync(path.dirname(sanitizedCheckPath), { recursive: true });
      fs.writeFileSync(sanitizedCheckPath, clean, 'utf8');
    }
  }

  const sanitizedSmellsPath = process.env.QUALITY_SANITIZED_SMELLS_SARIF;
  if (sanitizedSmellsPath && smellsSarifRaw) {
    const clean = sanitizeSarif(smellsSarifRaw);
    if (clean) {
      fs.mkdirSync(path.dirname(sanitizedSmellsPath), { recursive: true });
      fs.writeFileSync(sanitizedSmellsPath, clean, 'utf8');
    }
  }

  console.log(
    `Qlty Gate: ${report.outcome} (scope=${report.scope}, enforcement=${report.enforcement}, blocking=${report.counts.blocking}, advisory=${report.counts.advisory}, errors=${report.systemErrors.length})`,
  );

  if (!report.passed) {
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  runCli();
}
