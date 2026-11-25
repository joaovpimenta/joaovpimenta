import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  computeCoverageMetrics,
  detectAndParseCoverage,
  discoverTestReports,
  evaluateQualityGate,
  formatConfigErrorSummary,
  formatMarkdownSummary,
  mergeCoverageMaps,
  parseCoberturaXml,
  parseJacocoXml,
  parseJunitXml,
  parseLcov,
  parseMetricsOutput,
  parseSarif,
  parseUnifiedDiffAddedLines,
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

test('parses qlty metrics --functions output and flags cyclomatic complexity violations', () => {
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

  const parsed = parseMetricsOutput(sample, 5, 10);
  assert.equal(parsed.totalFunctions, 3);
  assert.equal(parsed.overCyclo10, 2);
  assert.equal(parsed.overCognitive15, 2);
  assert.equal(parsed.cyclomaticViolations.length, 2);
  assert.equal(parsed.cyclomaticViolations[0].name, 'LabHarness');
  assert.equal(parsed.topHotspots[0].name, 'SequenceInput');

  const blocked = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'standard',
    configValidateExit: 0,
    checkExit: 0,
    checkSarifRaw: sarif([]),
    smellsEnabled: false,
    metricsEnabled: true,
    metricsExit: 0,
    metricsRaw: sample,
    maxCyclomatic: 10,
  });
  assert.equal(blocked.passed, false);
  assert.equal(blocked.outcome, 'FAIL');
  assert.equal(blocked.gateViolations[0].category, 'cyclomatic');
  assert.match(formatMarkdownSummary(blocked), /Cyclomatic Complexity Violations \(> 10\)/);

  const advisory = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'report-only',
    configValidateExit: 0,
    checkExit: 0,
    checkSarifRaw: sarif([]),
    smellsEnabled: false,
    metricsEnabled: true,
    metricsExit: 0,
    metricsRaw: sample,
    maxCyclomatic: 10,
  });
  assert.equal(advisory.passed, true);
});

test('parses LCOV, JaCoCo XML, and Cobertura XML coverage formats accurately', () => {
  const lcov = parseLcov(`
TN:
SF:/home/runner/work/are/are/src/math.ts
DA:1,1
DA:2,1
DA:3,0
LF:3
LH:2
end_of_record
`);
  assert.equal(lcov.format, 'lcov');
  assert.equal(lcov.files.get('src/math.ts').get(1), 1);
  assert.equal(lcov.files.get('src/math.ts').get(3), 0);

  const jacoco = parseJacocoXml(`
<report name="demo">
  <package name="com/example/service">
    <sourcefile name="OrderService.java">
      <line nr="10" mi="0" ci="4" mb="0" cb="0"/>
      <line nr="11" mi="3" ci="0" mb="0" cb="0"/>
    </sourcefile>
  </package>
</report>
`);
  assert.equal(jacoco.format, 'jacoco');
  assert.equal(jacoco.files.get('com/example/service/OrderService.java').get(10), 4);
  assert.equal(jacoco.files.get('com/example/service/OrderService.java').get(11), 0);

  const cobertura = parseCoberturaXml(`
<coverage version="1">
  <packages>
    <package name="app">
      <classes>
        <class name="calc.py" filename="app/calc.py">
          <lines>
            <line number="5" hits="2"/>
            <line number="6" hits="0"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
`);
  assert.equal(cobertura.format, 'cobertura');
  assert.equal(cobertura.files.get('app/calc.py').get(5), 2);
  assert.equal(cobertura.files.get('app/calc.py').get(6), 0);

  assert.equal(detectAndParseCoverage('SF:src/a.js\nDA:1,1\nend_of_record\n', 'lcov.info').format, 'lcov');
});

test('computes total and diff coverage accurately including JaCoCo package suffix matching', () => {
  const jacoco = parseJacocoXml(`
<report name="java-app">
  <package name="com/acme/billing">
    <sourcefile name="Invoice.java">
      <line nr="1" mi="0" ci="2"/>
      <line nr="2" mi="0" ci="2"/>
      <line nr="3" mi="0" ci="2"/>
      <line nr="4" mi="0" ci="2"/>
      <line nr="5" mi="0" ci="2"/>
      <line nr="6" mi="0" ci="2"/>
      <line nr="7" mi="0" ci="2"/>
      <line nr="8" mi="0" ci="2"/>
      <line nr="9" mi="0" ci="2"/>
      <line nr="10" mi="3" ci="0"/>
    </sourcefile>
  </package>
</report>
`);

  const diff = `
diff --git a/src/main/java/com/acme/billing/Invoice.java b/src/main/java/com/acme/billing/Invoice.java
--- a/src/main/java/com/acme/billing/Invoice.java
+++ b/src/main/java/com/acme/billing/Invoice.java
@@ -8,0 +9,2 @@
+    return total;
+    logUnreachable();
`;

  const added = parseUnifiedDiffAddedLines(diff);
  const metrics = computeCoverageMetrics(mergeCoverageMaps([jacoco]), added);
  assert.equal(metrics.totalPct, 90);
  assert.equal(metrics.diffLinesFound, 2);
  assert.equal(metrics.diffLinesHit, 1);
  assert.equal(metrics.diffPct, 50);
  assert.deepEqual(metrics.uncoveredDiffLines, [
    { file: 'src/main/java/com/acme/billing/Invoice.java', line: 10 },
  ]);
});

test('parses JUnit XML without double-counting testsuites and enforces coverage + test thresholds', () => {
  const junit = parseJunitXml(`
<testsuites tests="4" failures="0" errors="0" skipped="1">
  <testsuite name="suiteA" tests="2" failures="0" errors="0" skipped="0"/>
  <testsuite name="suiteB" tests="2" failures="0" errors="0" skipped="1"/>
</testsuites>
`);
  assert.deepEqual(junit, {
    suites: 2,
    total: 4,
    failures: 0,
    errors: 0,
    skipped: 1,
    passed: 3,
  });

  const cov = parseLcov(`
SF:src/a.ts
DA:1,1
DA:2,1
DA:3,1
DA:4,1
DA:5,1
DA:6,1
DA:7,1
DA:8,1
DA:9,1
DA:10,0
end_of_record
`);
  const diff = `
+++ b/src/a.ts
@@ -1,0 +1,2 @@
+a
+b
`;

  const passReport = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'standard',
    configValidateExit: 0,
    checkExit: 0,
    checkSarifRaw: sarif([]),
    smellsEnabled: false,
    metricsEnabled: false,
    coverageMode: 'required',
    minCoverageTotal: 90,
    minCoverageDiff: 90,
    minTests: 4,
    allowSkippedTests: true,
    coverageReports: [cov],
    junitReports: [junit],
    diffRaw: diff,
  });
  assert.equal(passReport.passed, true);
  assert.equal(passReport.coverage.totalPct, 90);
  assert.equal(passReport.coverage.diffPct, 100);
  assert.match(formatMarkdownSummary(passReport), /Total line coverage/);

  const failSkipped = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'standard',
    configValidateExit: 0,
    checkExit: 0,
    checkSarifRaw: sarif([]),
    smellsEnabled: false,
    metricsEnabled: false,
    coverageMode: 'required',
    minCoverageTotal: 95,
    minCoverageDiff: 90,
    minTests: 10,
    allowSkippedTests: false,
    coverageReports: [cov],
    junitReports: [junit],
    diffRaw: diff,
  });
  assert.equal(failSkipped.passed, false);
  assert.equal(failSkipped.outcome, 'FAIL');
  assert.equal(failSkipped.gateViolations.length, 3);
});

test('fails closed when QLTY_COVERAGE_MODE=required and coverage or JUnit reports are missing', () => {
  const report = evaluateQualityGate({
    scope: 'pr',
    enforcement: 'standard',
    configValidateExit: 0,
    checkExit: 0,
    checkSarifRaw: sarif([]),
    smellsEnabled: false,
    metricsEnabled: false,
    coverageMode: 'required',
    minCoverageTotal: 90,
    minCoverageDiff: 90,
    minTests: 1,
    coverageReports: [],
    junitReports: [],
  });
  assert.equal(report.passed, false);
  assert.equal(report.outcome, 'ERROR');
  assert.equal(report.systemErrors.length, 2);
  assert.match(report.systemErrors[0], /A esteira precisa ser corrigida/i);
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
  assert.equal(result.problems.length, 8);
  for (const name of [
    'QLTY_SCOPE',
    'QLTY_ENFORCEMENT',
    'QLTY_VERSION',
    'QLTY_POLICY_REF',
    'QLTY_ENABLE_SMELLS',
    'QLTY_ENABLE_METRICS',
    'QLTY_MAX_CYCLOMATIC',
    'QLTY_COVERAGE_MODE',
  ]) {
    assert.ok(result.problems.some((p) => p.includes(name)), `Expected missing var ${name} to be reported`);
  }

  const summary = formatConfigErrorSummary(result);
  assert.match(summary, /A esteira precisa ser corrigida/i);
  assert.match(summary, /QLTY_MIN_COVERAGE_TOTAL/);
});

test('validateProjectVariables enforces coverage variables when QLTY_COVERAGE_MODE=required and rejects inconsistent cyclomatic config', () => {
  const missingCov = validateProjectVariables({
    QLTY_SCOPE: 'pr',
    QLTY_ENFORCEMENT: 'standard',
    QLTY_VERSION: '0.672.0',
    QLTY_POLICY_REF: 'qlty-v0.3.0',
    QLTY_ENABLE_SMELLS: 'true',
    QLTY_ENABLE_METRICS: 'false',
    QLTY_MAX_CYCLOMATIC: '10',
    QLTY_COVERAGE_MODE: 'required',
  });
  assert.equal(missingCov.valid, false);
  assert.equal(missingCov.problems.length, 4);
  assert.ok(missingCov.problems.some((p) => p.includes('QLTY_ENABLE_METRICS=true')));
  assert.ok(missingCov.problems.some((p) => p.includes('QLTY_MIN_COVERAGE_TOTAL')));
  assert.ok(missingCov.problems.some((p) => p.includes('QLTY_MIN_COVERAGE_DIFF')));
  assert.ok(missingCov.problems.some((p) => p.includes('QLTY_MIN_TESTS')));
});

test('validateProjectVariables resolves valid project variables and applies optional overrides', () => {
  const result = validateProjectVariables(
    {
      QLTY_SCOPE: 'pr',
      QLTY_ENFORCEMENT: 'standard',
      QLTY_VERSION: '0.672.0',
      QLTY_POLICY_REF: 'qlty-v0.3.0',
      QLTY_ENABLE_SMELLS: 'true',
      QLTY_ENABLE_METRICS: 'true',
      QLTY_MAX_CYCLOMATIC: '10',
      QLTY_COVERAGE_MODE: 'required',
      QLTY_MIN_COVERAGE_TOTAL: '90',
      QLTY_MIN_COVERAGE_DIFF: '90',
      QLTY_MIN_TESTS: '5',
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
    policyRef: 'qlty-v0.3.0',
    enableSmells: true,
    enableMetrics: true,
    maxCyclomatic: 10,
    coverageMode: 'required',
    minCoverageTotal: 90,
    minCoverageDiff: 90,
    minTests: 5,
    blockSmells: false,
    allowSkippedTests: true,
    diffFailOnEmpty: false,
    advisoryPlugins: 'osv-scanner,zizmor',
    artifactRetentionDays: 7,
  });
});

test('discoverTestReports auto-detects mixed LCOV, JaCoCo, and JUnit files in a directory', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qlty-reports-'));
  try {
    fs.mkdirSync(path.join(tmpDir, 'nested'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'lcov.info'), 'SF:src/a.ts\nDA:1,1\nend_of_record\n', 'utf8');
    fs.writeFileSync(
      path.join(tmpDir, 'nested', 'TEST-App.xml'),
      '<testsuite name="App" tests="3" failures="0" errors="0" skipped="0"/>',
      'utf8',
    );
    const found = discoverTestReports(tmpDir);
    assert.equal(found.coverageReports.length, 1);
    assert.equal(found.junitReports.length, 1);
    assert.equal(found.junitReports[0].total, 3);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
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
  assert.match(res.stderr, /QUALITY_COVERAGE_MODE/);
});
