import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  evaluateQualityGate,
  formatConfigErrorSummary,
  formatMarkdownSummary,
  parseMetricsOutput,
  parseSarif,
  redactText,
  sanitizeSarif,
  validateProjectVariables,
} from './quality-gate.mjs';

function sarif(results = []) {
  return JSON.stringify({
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'qlty' } },
        results,
      },
    ],
  });
}

function finding({ ruleId, level = 'warning', message = 'Issue', file = 'src/app.ts', line = 10, taxa = [] }) {
  return {
    ruleId,
    level,
    message: { text: message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: file },
          region: { startLine: line },
        },
      },
    ],
    taxa: taxa.map((id) => ({ id })),
  };
}

test('passes when check and smells are clean', () => {
  const report = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'standard',
    qltyVersion: '0.672.0',
    baseRef: 'origin/main',
    configValidateExit: 0,
    checkExit: 0,
    checkSarifRaw: sarif([]),
    smellsEnabled: true,
    smellsExit: 0,
    smellsSarifRaw: sarif([]),
    metricsEnabled: false,
  });

  assert.equal(report.passed, true);
  assert.equal(report.outcome, 'PASS');
  assert.equal(report.counts.total, 0);
});

test('fails standard gate on high-confidence error finding from blocking analyzer', () => {
  const report = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'standard',
    configValidateExit: 0,
    checkExit: 1,
    checkSarifRaw: sarif([
      finding({
        ruleId: 'actionlint:expression',
        level: 'error',
        message: 'property "foo" is not defined',
        file: '.github/workflows/ci.yml',
        line: 22,
      }),
    ]),
    smellsEnabled: true,
    smellsExit: 0,
    smellsSarifRaw: sarif([]),
    metricsEnabled: false,
  });

  assert.equal(report.passed, false);
  assert.equal(report.outcome, 'FAIL');
  assert.equal(report.counts.blocking, 1);
  assert.equal(report.counts.advisory, 0);
});

test('keeps advisory smells visible without blocking in standard mode', () => {
  const report = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'standard',
    configValidateExit: 0,
    checkExit: 0,
    checkSarifRaw: sarif([]),
    smellsEnabled: true,
    smellsExit: 0,
    smellsSarifRaw: sarif([
      finding({
        ruleId: 'qlty:function-complexity',
        level: 'warning',
        message: 'Function with high complexity (count = 16): renderScene',
        file: 'engine/src/scene.ts',
        line: 40,
        taxa: ['structure'],
      }),
      finding({
        ruleId: 'qlty:nested-control-flow',
        level: 'warning',
        message: 'Deeply nested control flow (count = 4)',
        file: 'engine/src/scene.ts',
        line: 52,
        taxa: ['structure'],
      }),
    ]),
    metricsEnabled: false,
  });

  assert.equal(report.passed, true);
  assert.equal(report.outcome, 'PASS');
  assert.equal(report.counts.blocking, 0);
  assert.equal(report.counts.advisory, 2);
});

test('blocks maintainability smells when blockSmells or strict mode is enabled', () => {
  const smells = sarif([
    finding({
      ruleId: 'qlty:function-complexity',
      level: 'warning',
      message: 'Function with high complexity (count = 16): complexFn',
      taxa: ['structure'],
    }),
  ]);

  const strictReport = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'strict',
    configValidateExit: 0,
    checkExit: 0,
    checkSarifRaw: sarif([]),
    smellsEnabled: true,
    smellsExit: 0,
    smellsSarifRaw: smells,
    metricsEnabled: false,
  });

  assert.equal(strictReport.passed, false);
  assert.equal(strictReport.outcome, 'FAIL');
  assert.equal(strictReport.counts.blocking, 1);
});

test('treats configured advisory plugins as non-blocking while still blocking secrets', () => {
  const report = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'standard',
    advisoryPlugins: ['osv-scanner', 'zizmor'],
    configValidateExit: 0,
    checkExit: 1,
    checkSarifRaw: sarif([
      finding({
        ruleId: 'osv-scanner:CVE-2026-112949',
        level: 'warning',
        message: 'Existing dependency vulnerability',
        file: 'pnpm-lock.yaml',
        line: 1,
      }),
      finding({
        ruleId: 'zizmor:zizmor/unpinned-uses',
        level: 'error',
        message: 'Unpinned action reference',
        file: '.github/workflows/ci.yml',
        line: 10,
      }),
    ]),
    smellsEnabled: false,
    metricsEnabled: false,
  });

  assert.equal(report.passed, true);
  assert.equal(report.counts.advisory, 2);
  assert.equal(report.counts.blocking, 0);
});

test('blocks and redacts exposed secret findings in both JSON and Markdown summary', () => {
  const fakeToken = 'ghp_1234567890abcdefghijklmnopQRSTUV';
  const report = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'standard',
    configValidateExit: 0,
    checkExit: 1,
    checkSarifRaw: sarif([
      finding({
        ruleId: 'gitleaks:github-pat',
        level: 'error',
        message: `GitHub Personal Access Token detected: ${fakeToken}`,
        file: 'scripts/leak.ts',
        line: 3,
        taxa: ['secret'],
      }),
    ]),
    smellsEnabled: false,
    metricsEnabled: false,
  });

  const md = formatMarkdownSummary(report);
  assert.equal(report.passed, false);
  assert.equal(report.counts.secrets, 1);
  assert.equal(report.counts.blocking, 1);
  assert.ok(!md.includes(fakeToken), 'Markdown summary must never contain raw secret');
  assert.ok(!JSON.stringify(report).includes(fakeToken), 'JSON report must never contain raw secret');
  assert.match(md, /REDACTED/);
});

test('report-only mode reports findings without failing, but still fails closed on tool crashes', () => {
  const findingsReport = evaluateQualityGate({
    scope: 'full',
    enforcement: 'report-only',
    configValidateExit: 0,
    checkExit: 1,
    checkSarifRaw: sarif([
      finding({ ruleId: 'actionlint:expression', level: 'error', message: 'Syntax error' }),
    ]),
    smellsEnabled: false,
    metricsEnabled: false,
  });
  assert.equal(findingsReport.passed, true);
  assert.equal(findingsReport.counts.advisory, 1);

  const crashReport = evaluateQualityGate({
    scope: 'full',
    enforcement: 'report-only',
    configValidateExit: 0,
    checkExit: 99,
    checkSarifRaw: '',
    smellsEnabled: false,
    metricsEnabled: false,
  });
  assert.equal(crashReport.passed, false);
  assert.equal(crashReport.outcome, 'ERROR');
  assert.ok(crashReport.systemErrors.length >= 1);
});

test('fails closed on invalid TOML config, malformed SARIF, or missing smells report', () => {
  const invalidConfig = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'standard',
    configValidateExit: 2,
    checkExit: 0,
    checkSarifRaw: sarif([]),
    smellsEnabled: false,
    metricsEnabled: false,
  });
  assert.equal(invalidConfig.passed, false);
  assert.equal(invalidConfig.outcome, 'ERROR');

  const malformedSarif = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'standard',
    configValidateExit: 0,
    checkExit: 0,
    checkSarifRaw: '{not-valid-json',
    smellsEnabled: true,
    smellsExit: 0,
    smellsSarifRaw: undefined,
    metricsEnabled: false,
  });
  assert.equal(malformedSarif.passed, false);
  assert.equal(malformedSarif.outcome, 'ERROR');
  assert.equal(malformedSarif.systemErrors.length, 2);
});

test('parses qlty metrics --functions output and sorts hotspots by cognitive then cyclomatic complexity', () => {
  const sample = `
lab/src/harness/LabHarness.tsx

 function   | fields | cyclo | cognitive | lines | loc
------------+--------+-------+-----------+-------+-----
 LabHarness |      0 |    18 |        19 |   114 | 109
 navigate   |      0 |     1 |         0 |     4 |   4

engine/src/components/sequence/SequenceInput.tsx

 function      | fields | cyclo | cognitive | lines | loc
---------------+--------+-------+-----------+-------+-----
 SequenceInput |      0 |    13 |        22 |    66 |  61
`;

  const parsed = parseMetricsOutput(sample, 5);
  assert.equal(parsed.totalFunctions, 3);
  assert.equal(parsed.overCyclo10, 2);
  assert.equal(parsed.overCognitive15, 2);
  assert.equal(parsed.topHotspots[0].name, 'SequenceInput');
  assert.equal(parsed.topHotspots[1].name, 'LabHarness');
});

test('redactText masks common credential formats in arbitrary messages', () => {
  const input = 'Found AKIAIOSFODNN7EXAMPLE and Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdef123456 and password="supersecretvalue"';
  const redacted = redactText(input);
  assert.ok(!redacted.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!redacted.includes('supersecretvalue'));
  assert.ok(!redacted.includes('eyJhbGciOiJIUzI1NiJ9'));
});

test('parseSarif handles UTF-8 BOM and UTF-16LE buffers cleanly', () => {
  const raw = sarif([finding({ ruleId: 'eslint:complexity', level: 'error', message: 'Complexity 11' })]);
  const utf8Bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(raw, 'utf8')]);
  const utf16le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(raw, 'utf16le')]);

  assert.equal(parseSarif(utf8Bom).length, 1);
  assert.equal(parseSarif(utf16le).length, 1);
});

test('sanitizeSarif scrubs secret values, snippets, and secret partialFingerprints', () => {
  const fakeSecret = 'ghp_1234567890abcdefghijklmnopQRSTUV';
  const raw = JSON.stringify({
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'qlty' } },
        results: [
          {
            ruleId: 'gitleaks:github-pat',
            level: 'error',
            message: { text: `Leaked token: ${fakeSecret}` },
            partialFingerprints: { primary: 'abc123' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'src/config.ts' },
                  region: { startLine: 1, snippet: { text: `const t = "${fakeSecret}"` } },
                },
              },
            ],
            taxa: [{ id: 'secret' }],
          },
        ],
      },
    ],
  });

  const clean = sanitizeSarif(raw);
  assert.ok(clean);
  assert.ok(!clean.includes(fakeSecret));
  const parsed = JSON.parse(clean);
  assert.equal(parsed.runs[0].results[0].partialFingerprints, undefined);
  assert.equal(parsed.runs[0].results[0].locations[0].physicalLocation.region.snippet, undefined);
});

test('validateProjectVariables fails with explicit pipeline fix justification when required vars are missing', () => {
  const result = validateProjectVariables({});
  assert.equal(result.valid, false);
  assert.equal(result.config, null);
  assert.match(result.justification, /A esteira precisa ser corrigida/i);
  assert.equal(result.problems.length, 6);
  for (const name of [
    'QLTY_SCOPE',
    'QLTY_ENFORCEMENT',
    'QLTY_VERSION',
    'QLTY_POLICY_REF',
    'QLTY_ENABLE_SMELLS',
    'QLTY_ENABLE_METRICS',
  ]) {
    assert.ok(result.problems.some((p) => p.includes(name)), `Expected missing var ${name} to be reported`);
  }

  const summary = formatConfigErrorSummary(result);
  assert.match(summary, /A esteira precisa ser corrigida/i);
  assert.match(summary, /QLTY_POLICY_REF/);
});

test('validateProjectVariables rejects invalid values for required and optional vars', () => {
  const result = validateProjectVariables({
    QLTY_SCOPE: 'branch',
    QLTY_ENFORCEMENT: 'loose',
    QLTY_VERSION: 'latest',
    QLTY_POLICY_REF: 'bad ref with spaces',
    QLTY_ENABLE_SMELLS: 'yes',
    QLTY_ENABLE_METRICS: '1',
    QLTY_BLOCK_SMELLS: 'maybe',
    QLTY_ARTIFACT_RETENTION_DAYS: '120',
    QLTY_ADVISORY_PLUGINS: 'osv-scanner;rm -rf /',
  });

  assert.equal(result.valid, false);
  assert.equal(result.problems.length, 9);
});

test('validateProjectVariables resolves valid project variables and applies optional overrides', () => {
  const result = validateProjectVariables(
    {
      QLTY_SCOPE: 'pr',
      QLTY_ENFORCEMENT: 'standard',
      QLTY_VERSION: '0.672.0',
      QLTY_POLICY_REF: 'qlty-v0.2.0',
      QLTY_ENABLE_SMELLS: 'true',
      QLTY_ENABLE_METRICS: 'false',
      QLTY_ADVISORY_PLUGINS: 'osv-scanner, zizmor',
    },
    { scopeOverride: 'full', enforcementOverride: 'report-only' },
  );

  assert.equal(result.valid, true);
  assert.equal(result.justification, null);
  assert.deepEqual(result.config, {
    scope: 'full',
    enforcement: 'report-only',
    qltyVersion: '0.672.0',
    policyRef: 'qlty-v0.2.0',
    enableSmells: true,
    enableMetrics: false,
    blockSmells: false,
    advisoryPlugins: 'osv-scanner,zizmor',
    artifactRetentionDays: 7,
  });
});

test('CLI fails closed with pipeline fix justification when required QUALITY_* env vars are absent', () => {
  const scriptPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'quality-gate.mjs');
  const res = spawnSync(process.execPath, [scriptPath], {
    env: { PATH: process.env.PATH },
    encoding: 'utf8',
  });

  assert.equal(res.status, 1);
  assert.match(res.stderr, /A esteira precisa ser corrigida/i);
  assert.match(res.stderr, /QUALITY_SCOPE/);
  assert.match(res.stderr, /QUALITY_ENFORCEMENT/);
});
