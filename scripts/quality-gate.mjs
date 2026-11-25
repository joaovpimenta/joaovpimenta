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

export function normalizeRepoPath(filePath, workspaceRoot = '') {
  let normalized = String(filePath || '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^\.\//, '');

  if (workspaceRoot) {
    const cleanRoot = String(workspaceRoot)
      .trim()
      .replace(/\\/g, '/')
      .replace(/\/+$/, '');
    if (cleanRoot && normalized.startsWith(`${cleanRoot}/`)) {
      normalized = normalized.slice(cleanRoot.length + 1);
    }
  }

  // Handle GitHub Actions runner paths like /home/runner/work/repo/repo/src/...
  const runnerMatch = normalized.match(/^\/home\/runner\/work\/[^/]+\/[^/]+\/(.+)$/);
  if (runnerMatch) {
    normalized = runnerMatch[1];
  }

  return normalized.replace(/^\/+/, '');
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

export function parseMetricsOutput(rawText, topN = 10, maxCyclomatic = null) {
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
  const cyclomaticLimit = Number.isFinite(maxCyclomatic) ? maxCyclomatic : null;
  const cyclomaticViolations = cyclomaticLimit !== null
    ? functions
      .filter((fn) => fn.cyclo > cyclomaticLimit)
      .sort((a, b) => (b.cyclo - a.cyclo) || (b.cognitive - a.cognitive))
    : [];

  return {
    totalFunctions: functions.length,
    overCyclo10: functions.filter((fn) => fn.cyclo > 10).length,
    overCognitive15: functions.filter((fn) => fn.cognitive > 15).length,
    maxCyclomatic: cyclomaticLimit,
    cyclomaticViolations,
    topHotspots: functions.slice(0, topN),
  };
}

// ---------------------------------------------------------------------------
// Coverage parsers (LCOV, JaCoCo XML, Cobertura XML) + Unified Diff + JUnit
// ---------------------------------------------------------------------------

function mergeLineHit(filesMap, fileKey, lineNumber, hits) {
  if (!fileKey || !Number.isInteger(lineNumber) || lineNumber <= 0) return;
  let lineMap = filesMap.get(fileKey);
  if (!lineMap) {
    lineMap = new Map();
    filesMap.set(fileKey, lineMap);
  }
  const prev = lineMap.get(lineNumber) ?? 0;
  lineMap.set(lineNumber, Math.max(prev, hits));
}

function parseXmlAttrs(attrString) {
  const attrs = {};
  const attrRe = /([A-Za-z0-9_:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let match;
  while ((match = attrRe.exec(attrString)) !== null) {
    attrs[match[1]] = match[2] ?? match[3] ?? '';
  }
  return attrs;
}

export function parseLcov(rawContent, workspaceRoot = '') {
  const text = stripBomAndDecode(rawContent || '');
  const files = new Map();
  let currentFile = null;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith('SF:')) {
      currentFile = normalizeRepoPath(line.slice(3), workspaceRoot);
      if (currentFile && !files.has(currentFile)) {
        files.set(currentFile, new Map());
      }
      continue;
    }
    if (line === 'end_of_record') {
      currentFile = null;
      continue;
    }
    if (currentFile && line.startsWith('DA:')) {
      const parts = line.slice(3).split(',');
      const lineNumber = Number.parseInt(parts[0], 10);
      const hits = Number.parseInt(parts[1], 10);
      if (Number.isInteger(lineNumber) && Number.isFinite(hits)) {
        mergeLineHit(files, currentFile, lineNumber, Math.max(0, hits));
      }
    }
  }

  return { format: 'lcov', files };
}

export function parseJacocoXml(rawContent, workspaceRoot = '') {
  const text = stripBomAndDecode(rawContent || '');
  const files = new Map();

  const packageRe = /<package\b([^>]*)>([\s\S]*?)<\/package>/gi;
  let pkgMatch;
  while ((pkgMatch = packageRe.exec(text)) !== null) {
    const pkgAttrs = parseXmlAttrs(pkgMatch[1]);
    const pkgName = String(pkgAttrs.name || '').replace(/^\/+|\/+$/g, '');
    const pkgBody = pkgMatch[2];

    const sourceFileRe = /<sourcefile\b([^>]*)>([\s\S]*?)<\/sourcefile>/gi;
    let sfMatch;
    while ((sfMatch = sourceFileRe.exec(pkgBody)) !== null) {
      const sfAttrs = parseXmlAttrs(sfMatch[1]);
      const sfName = String(sfAttrs.name || '').trim();
      if (!sfName) continue;
      const key = normalizeRepoPath(pkgName ? `${pkgName}/${sfName}` : sfName, workspaceRoot);
      if (!files.has(key)) files.set(key, new Map());

      const lineRe = /<line\b([^>]*)\/?>/gi;
      let lineMatch;
      while ((lineMatch = lineRe.exec(sfMatch[2])) !== null) {
        const lineAttrs = parseXmlAttrs(lineMatch[1]);
        const nr = Number.parseInt(lineAttrs.nr, 10);
        const ci = Number.parseInt(lineAttrs.ci ?? '0', 10);
        const mi = Number.parseInt(lineAttrs.mi ?? '0', 10);
        if (Number.isInteger(nr) && (ci > 0 || mi > 0)) {
          mergeLineHit(files, key, nr, ci > 0 ? ci : 0);
        }
      }
    }
  }

  return { format: 'jacoco', files };
}

export function parseCoberturaXml(rawContent, workspaceRoot = '') {
  const text = stripBomAndDecode(rawContent || '');
  const files = new Map();

  const classRe = /<class\b([^>]*)>([\s\S]*?)<\/class>/gi;
  let classMatch;
  while ((classMatch = classRe.exec(text)) !== null) {
    const classAttrs = parseXmlAttrs(classMatch[1]);
    const filename = normalizeRepoPath(classAttrs.filename || '', workspaceRoot);
    if (!filename) continue;
    if (!files.has(filename)) files.set(filename, new Map());

    const lineRe = /<line\b([^>]*)\/?>/gi;
    let lineMatch;
    while ((lineMatch = lineRe.exec(classMatch[2])) !== null) {
      const lineAttrs = parseXmlAttrs(lineMatch[1]);
      const nr = Number.parseInt(lineAttrs.number, 10);
      const hits = Number.parseInt(lineAttrs.hits ?? '0', 10);
      if (Number.isInteger(nr) && Number.isFinite(hits)) {
        mergeLineHit(files, filename, nr, Math.max(0, hits));
      }
    }
  }

  return { format: 'cobertura', files };
}

export function detectAndParseCoverage(rawContent, fileName = '', workspaceRoot = '') {
  const text = stripBomAndDecode(rawContent || '').trim();
  if (!text) return null;

  const lower = String(fileName || '').toLowerCase();
  if (lower.endsWith('.info') || /^TN:|^SF:/m.test(text)) {
    const parsed = parseLcov(text, workspaceRoot);
    if (parsed.files.size > 0) return parsed;
  }

  if (/<report\b/i.test(text) && /<sourcefile\b/i.test(text)) {
    const parsed = parseJacocoXml(text, workspaceRoot);
    if (parsed.files.size > 0) return parsed;
  }

  if (/<coverage\b/i.test(text) && /<class\b/i.test(text)) {
    const parsed = parseCoberturaXml(text, workspaceRoot);
    if (parsed.files.size > 0) return parsed;
  }

  return null;
}

export function mergeCoverageMaps(parsedReports) {
  const merged = new Map();
  const formats = new Set();
  for (const report of parsedReports || []) {
    if (!report || !(report.files instanceof Map)) continue;
    if (report.format) formats.add(report.format);
    for (const [fileKey, lineMap] of report.files.entries()) {
      if (!merged.has(fileKey)) merged.set(fileKey, new Map());
      for (const [lineNumber, hits] of lineMap.entries()) {
        mergeLineHit(merged, fileKey, lineNumber, hits);
      }
    }
  }
  return {
    formats: [...formats],
    files: merged,
  };
}

export function parseUnifiedDiffAddedLines(diffText, workspaceRoot = '') {
  const text = stripBomAndDecode(diffText || '');
  const addedByFile = new Map();
  let currentFile = null;

  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('+++ ')) {
      const target = line.slice(4).trim();
      if (target === '/dev/null') {
        currentFile = null;
      } else {
        const cleaned = target.replace(/^b\//, '');
        currentFile = normalizeRepoPath(cleaned, workspaceRoot);
        if (currentFile && !addedByFile.has(currentFile)) {
          addedByFile.set(currentFile, new Set());
        }
      }
      continue;
    }

    if (currentFile && line.startsWith('@@ ')) {
      const hunkMatch = line.match(/\+(\d+)(?:,(\d+))?/);
      if (hunkMatch) {
        const start = Number.parseInt(hunkMatch[1], 10);
        const count = hunkMatch[2] === undefined ? 1 : Number.parseInt(hunkMatch[2], 10);
        if (Number.isInteger(start) && Number.isInteger(count) && count > 0) {
          const lineSet = addedByFile.get(currentFile);
          for (let nr = start; nr < start + count; nr++) {
            lineSet.add(nr);
          }
        }
      }
    }
  }

  return addedByFile;
}

function findCoverageForDiffFile(diffFile, coverageFilesMap) {
  if (coverageFilesMap.has(diffFile)) {
    return coverageFilesMap.get(diffFile);
  }
  // Suffix fallback for JaCoCo/Kover XML where paths are `com/example/Foo.java`
  // while git diff reports `src/main/java/com/example/Foo.java` or `app/src/main/kotlin/...`
  let bestMatch = null;
  let bestLen = -1;
  for (const [covFile, lineMap] of coverageFilesMap.entries()) {
    if (diffFile.endsWith(`/${covFile}`) && covFile.length > bestLen) {
      bestMatch = lineMap;
      bestLen = covFile.length;
    } else if (covFile.endsWith(`/${diffFile}`) && diffFile.length > bestLen) {
      bestMatch = lineMap;
      bestLen = diffFile.length;
    }
  }
  return bestMatch;
}

export function computeCoverageMetrics(mergedCoverage, diffAddedByFile = null) {
  let totalLinesFound = 0;
  let totalLinesHit = 0;
  const filesMap = mergedCoverage?.files || new Map();

  for (const lineMap of filesMap.values()) {
    for (const hits of lineMap.values()) {
      totalLinesFound++;
      if (hits > 0) totalLinesHit++;
    }
  }

  const totalPct = totalLinesFound > 0 ? roundPct((totalLinesHit / totalLinesFound) * 100) : null;

  let diffLinesFound = 0;
  let diffLinesHit = 0;
  const uncoveredDiffLines = [];

  if (diffAddedByFile instanceof Map && diffAddedByFile.size > 0) {
    for (const [diffFile, lineSet] of diffAddedByFile.entries()) {
      const covLines = findCoverageForDiffFile(diffFile, filesMap);
      if (!covLines) continue;
      for (const lineNumber of [...lineSet].sort((a, b) => a - b)) {
        if (!covLines.has(lineNumber)) continue;
        diffLinesFound++;
        if (covLines.get(lineNumber) > 0) {
          diffLinesHit++;
        } else {
          uncoveredDiffLines.push({ file: diffFile, line: lineNumber });
        }
      }
    }
  }

  const diffPct = diffLinesFound > 0 ? roundPct((diffLinesHit / diffLinesFound) * 100) : null;

  return {
    formats: mergedCoverage?.formats || [],
    filesTracked: filesMap.size,
    totalLinesFound,
    totalLinesHit,
    totalPct,
    diffLinesFound,
    diffLinesHit,
    diffPct,
    uncoveredDiffLines,
  };
}

function roundPct(value) {
  return Math.round(value * 100) / 100;
}

export function parseJunitXml(rawContent) {
  const text = stripBomAndDecode(rawContent || '').trim();
  if (!text || !/<testsuite(?:s)?\b/i.test(text)) {
    return null;
  }

  // Prefer leaf <testsuite> tags to avoid double counting <testsuites> aggregates.
  const suiteMatches = [...text.matchAll(/<testsuite\b([^>]*)(?:\/>|>)/gi)];
  let total = 0;
  let failures = 0;
  let errors = 0;
  let skipped = 0;
  let suitesCount = 0;

  if (suiteMatches.length > 0) {
    for (const match of suiteMatches) {
      const attrs = parseXmlAttrs(match[1]);
      if (attrs.tests !== undefined) {
        suitesCount++;
        total += Number.parseInt(attrs.tests, 10) || 0;
        failures += Number.parseInt(attrs.failures ?? '0', 10) || 0;
        errors += Number.parseInt(attrs.errors ?? '0', 10) || 0;
        skipped += Number.parseInt(attrs.skipped ?? attrs.disabled ?? '0', 10) || 0;
      }
    }
  }

  if (suitesCount === 0) {
    const rootMatch = text.match(/<testsuites\b([^>]*)>/i);
    if (rootMatch) {
      const attrs = parseXmlAttrs(rootMatch[1]);
      if (attrs.tests !== undefined) {
        suitesCount = 1;
        total = Number.parseInt(attrs.tests, 10) || 0;
        failures = Number.parseInt(attrs.failures ?? '0', 10) || 0;
        errors = Number.parseInt(attrs.errors ?? '0', 10) || 0;
        skipped = Number.parseInt(attrs.skipped ?? attrs.disabled ?? '0', 10) || 0;
      }
    }
  }

  if (suitesCount === 0) {
    const testcases = [...text.matchAll(/<testcase\b[^>]*?(?:\/>|>[\s\S]*?<\/testcase>)/gi)];
    if (testcases.length === 0) return null;
    suitesCount = 1;
    total = testcases.length;
    for (const tc of testcases) {
      if (/<failure\b/i.test(tc[0])) failures++;
      else if (/<error\b/i.test(tc[0])) errors++;
      else if (/<skipped\b/i.test(tc[0])) skipped++;
    }
  }

  return {
    suites: suitesCount,
    total,
    failures,
    errors,
    skipped,
    passed: Math.max(0, total - failures - errors - skipped),
  };
}

export function discoverTestReports(rootDir, workspaceRoot = '') {
  const coverageReports = [];
  const junitReports = [];
  const coverageFiles = [];
  const junitFiles = [];

  if (!rootDir || !fs.existsSync(rootDir)) {
    return { coverageReports, junitReports, coverageFiles, junitFiles };
  }

  const stack = [rootDir];
  while (stack.length > 0) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const lower = entry.name.toLowerCase();
      if (!lower.endsWith('.info') && !lower.endsWith('.xml') && !lower.endsWith('.lcov')) {
        continue;
      }
      const content = fs.readFileSync(fullPath);
      const cov = detectAndParseCoverage(content, entry.name, workspaceRoot);
      if (cov) {
        coverageReports.push(cov);
        coverageFiles.push(path.relative(rootDir, fullPath).replace(/\\/g, '/'));
        continue;
      }
      if (lower.endsWith('.xml')) {
        const junit = parseJunitXml(content);
        if (junit) {
          junitReports.push(junit);
          junitFiles.push(path.relative(rootDir, fullPath).replace(/\\/g, '/'));
        }
      }
    }
  }

  return { coverageReports, junitReports, coverageFiles, junitFiles };
}

export function mergeJunitReports(reports) {
  if (!reports || reports.length === 0) return null;
  const agg = { suites: 0, total: 0, passed: 0, failures: 0, errors: 0, skipped: 0 };
  for (const r of reports) {
    if (!r) continue;
    agg.suites += r.suites || 0;
    agg.total += r.total || 0;
    agg.passed += r.passed || 0;
    agg.failures += r.failures || 0;
    agg.errors += r.errors || 0;
    agg.skipped += r.skipped || 0;
  }
  return agg;
}

// ---------------------------------------------------------------------------
// Gate classification & evaluation
// ---------------------------------------------------------------------------

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
  const maxCyclomatic = Number.isFinite(input.maxCyclomatic) ? input.maxCyclomatic : null;
  const coverageMode = input.coverageMode || 'none';
  const minCoverageTotal = Number.isFinite(input.minCoverageTotal) ? input.minCoverageTotal : null;
  const minCoverageDiff = Number.isFinite(input.minCoverageDiff) ? input.minCoverageDiff : null;
  const minTests = Number.isFinite(input.minTests) ? input.minTests : null;
  const allowSkippedTests = input.allowSkippedTests !== false;
  const diffFailOnEmpty = Boolean(input.diffFailOnEmpty);

  const systemErrors = [];
  const gateViolations = [];

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
      metrics = parseMetricsOutput(input.metricsRaw || '', 10, maxCyclomatic);
      if (maxCyclomatic !== null && metrics.cyclomaticViolations.length > 0) {
        const blocking = enforcement !== 'report-only';
        gateViolations.push({
          category: 'cyclomatic',
          blocking,
          message: `${metrics.cyclomaticViolations.length} function(s) exceed QLTY_MAX_CYCLOMATIC=${maxCyclomatic} (worst: ${metrics.cyclomaticViolations[0].name} cyclo=${metrics.cyclomaticViolations[0].cyclo}).`,
        });
      }
    }
  } else if (maxCyclomatic !== null) {
    systemErrors.push('QLTY_MAX_CYCLOMATIC is set, but QLTY_ENABLE_METRICS is false.');
  }

  // Coverage & test suite evaluation
  let coverage = null;
  let testSuite = null;
  if (coverageMode === 'required') {
    const coverageReports = input.coverageReports || [];
    const junitReports = input.junitReports || [];

    if (coverageReports.length === 0) {
      systemErrors.push(
        'A esteira precisa ser corrigida: QLTY_COVERAGE_MODE=required, mas nenhum relatório de cobertura (LCOV, JaCoCo XML ou Cobertura XML) foi encontrado.',
      );
    } else {
      const mergedCov = mergeCoverageMaps(coverageReports);
      const diffAdded = input.diffRaw
        ? parseUnifiedDiffAddedLines(input.diffRaw, input.workspaceRoot || '')
        : null;
      coverage = computeCoverageMetrics(mergedCov, diffAdded);
      coverage.thresholds = {
        total: minCoverageTotal,
        diff: minCoverageDiff,
      };

      if (coverage.totalLinesFound === 0) {
        systemErrors.push('Relatório de cobertura encontrado, mas com 0 linhas instrumentadas.');
      } else if (minCoverageTotal !== null && coverage.totalPct < minCoverageTotal) {
        gateViolations.push({
          category: 'coverage-total',
          blocking: enforcement !== 'report-only',
          message: `Cobertura geral (${coverage.totalPct.toFixed(2)}%) abaixo do mínimo exigido (${minCoverageTotal}%).`,
        });
      }

      if (scope === 'pr' && minCoverageDiff !== null) {
        if (coverage.diffLinesFound > 0) {
          if (coverage.diffPct < minCoverageDiff) {
            gateViolations.push({
              category: 'coverage-diff',
              blocking: enforcement !== 'report-only',
              message: `Cobertura de código novo (${coverage.diffPct.toFixed(2)}%) abaixo do mínimo exigido (${minCoverageDiff}%) em ${coverage.diffLinesFound} linha(s) executável(is) alterada(s).`,
            });
          }
        } else if (diffFailOnEmpty) {
          gateViolations.push({
            category: 'coverage-diff',
            blocking: enforcement !== 'report-only',
            message: 'Nenhuma linha executável alterada no diff correspondeu ao relatório de cobertura (QLTY_COVERAGE_DIFF_FAIL_ON_EMPTY=true).',
          });
        }
      }
    }

    if (minTests !== null) {
      if (junitReports.length === 0) {
        systemErrors.push(
          'A esteira precisa ser corrigida: QLTY_MIN_TESTS está ativo, mas nenhum relatório JUnit XML foi encontrado.',
        );
      } else {
        testSuite = mergeJunitReports(junitReports);
        testSuite.minTests = minTests;
        testSuite.allowSkippedTests = allowSkippedTests;

        if (testSuite.total < minTests) {
          gateViolations.push({
            category: 'test-count',
            blocking: enforcement !== 'report-only',
            message: `Quantidade de testes executados (${testSuite.total}) abaixo do mínimo exigido (QLTY_MIN_TESTS=${minTests}).`,
          });
        }
        if (testSuite.failures > 0 || testSuite.errors > 0) {
          gateViolations.push({
            category: 'test-failures',
            blocking: enforcement !== 'report-only',
            message: `Relatório JUnit contém ${testSuite.failures} falha(s) e ${testSuite.errors} erro(s).`,
          });
        }
        if (!allowSkippedTests && testSuite.skipped > 0) {
          gateViolations.push({
            category: 'test-skipped',
            blocking: enforcement !== 'report-only',
            message: `Relatório JUnit contém ${testSuite.skipped} teste(s) ignorado(s) (QLTY_ALLOW_SKIPPED_TESTS=false).`,
          });
        }
      }
    }
  }

  const allFindings = [...checkFindings, ...smellFindings].map((finding) => ({
    ...finding,
    gate: classifyFinding(finding, { enforcement, advisoryPlugins, blockSmells }),
  }));

  const blockingFindings = allFindings.filter((item) => item.gate.blocking);
  const advisoryFindings = allFindings.filter((item) => !item.gate.blocking);
  const blockingGateViolations = gateViolations.filter((item) => item.blocking);

  const byPlugin = {};
  const byLevel = { error: 0, warning: 0, note: 0 };
  for (const item of allFindings) {
    byPlugin[item.plugin] = byPlugin[item.plugin] || { total: 0, blocking: 0, advisory: 0 };
    byPlugin[item.plugin].total++;
    if (item.gate.blocking) byPlugin[item.plugin].blocking++;
    else byPlugin[item.plugin].advisory++;
    byLevel[item.level] = (byLevel[item.level] || 0) + 1;
  }

  const passed = systemErrors.length === 0
    && blockingFindings.length === 0
    && blockingGateViolations.length === 0;
  const outcome = systemErrors.length > 0
    ? 'ERROR'
    : (blockingFindings.length > 0 || blockingGateViolations.length > 0)
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
      coverage: coverageMode === 'required' ? (coverage ? 'ran' : 'error') : 'skipped',
      tests: (coverageMode === 'required' && minTests !== null) ? (testSuite ? 'ran' : 'error') : 'skipped',
    },
    counts: {
      total: allFindings.length,
      blocking: blockingFindings.length + blockingGateViolations.length,
      blockingFindings: blockingFindings.length,
      blockingGateViolations: blockingGateViolations.length,
      advisory: advisoryFindings.length,
      secrets: allFindings.filter((item) => item.isSecret).length,
      byLevel,
      byPlugin,
    },
    systemErrors,
    gateViolations,
    blockingFindings,
    advisoryFindings,
    metrics,
    coverage,
    testSuite,
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
    `- **Stages:** config=\`${report.checks.configValidate}\`, check=\`${report.checks.check}\`, smells=\`${report.checks.smells}\`, metrics=\`${report.checks.metrics}\`, coverage=\`${report.checks.coverage}\`, tests=\`${report.checks.tests}\``,
  );
  lines.push(
    `- **Findings:** ${report.counts.total} static (${report.counts.blocking} total blocking, ${report.counts.advisory} advisory, ${report.counts.secrets} secret)`,
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

  if (report.gateViolations && report.gateViolations.length > 0) {
    lines.push('### Threshold Gate Violations');
    lines.push('');
    lines.push('| Category | Mode | Detail |');
    lines.push('|---|---|---|');
    for (const v of report.gateViolations) {
      lines.push(`| \`${escapeMd(v.category)}\` | ${v.blocking ? 'blocking' : 'advisory'} | ${escapeMd(v.message)} |`);
    }
    lines.push('');
  }

  if (report.coverage || report.testSuite) {
    lines.push('### Coverage & Test Suite');
    lines.push('');
    lines.push('| Metric | Value | Threshold | Status |');
    lines.push('|---|---:|---:|---|');
    if (report.coverage) {
      const totalVal = report.coverage.totalPct !== null
        ? `${report.coverage.totalPct.toFixed(2)}% (${report.coverage.totalLinesHit}/${report.coverage.totalLinesFound})`
        : 'N/A';
      const totalMin = report.coverage.thresholds?.total;
      const totalOk = totalMin === null || (report.coverage.totalPct !== null && report.coverage.totalPct >= totalMin);
      lines.push(`| Total line coverage | ${totalVal} | ${totalMin !== null ? `>= ${totalMin}%` : '-'} | ${totalOk ? 'PASS' : 'FAIL'} |`);

      const diffMin = report.coverage.thresholds?.diff;
      const diffVal = report.coverage.diffLinesFound > 0
        ? `${report.coverage.diffPct.toFixed(2)}% (${report.coverage.diffLinesHit}/${report.coverage.diffLinesFound})`
        : 'N/A (0 executable diff lines)';
      const diffOk = diffMin === null
        || report.coverage.diffLinesFound === 0
        || (report.coverage.diffPct !== null && report.coverage.diffPct >= diffMin);
      lines.push(`| New-code (diff) coverage | ${diffVal} | ${diffMin !== null ? `>= ${diffMin}%` : '-'} | ${diffOk ? 'PASS' : 'FAIL'} |`);
    }
    if (report.testSuite) {
      const testOk = report.testSuite.total >= (report.testSuite.minTests ?? 0)
        && report.testSuite.failures === 0
        && report.testSuite.errors === 0
        && (report.testSuite.allowSkippedTests || report.testSuite.skipped === 0);
      lines.push(
        `| Tests executed (JUnit) | ${report.testSuite.total} (${report.testSuite.passed} passed, ${report.testSuite.failures} failed, ${report.testSuite.errors} errors, ${report.testSuite.skipped} skipped) | >= ${report.testSuite.minTests ?? 0} | ${testOk ? 'PASS' : 'FAIL'} |`,
      );
    }
    lines.push('');

    if (report.coverage?.uncoveredDiffLines?.length > 0) {
      lines.push('#### Uncovered New / Modified Lines (Top 25)');
      lines.push('');
      for (const item of report.coverage.uncoveredDiffLines.slice(0, 25)) {
        lines.push(`- \`${escapeMd(item.file)}:${item.line}\``);
      }
      if (report.coverage.uncoveredDiffLines.length > 25) {
        lines.push(`- _...and ${report.coverage.uncoveredDiffLines.length - 25} more uncovered diff lines._`);
      }
      lines.push('');
    }
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

  if (report.metrics?.cyclomaticViolations?.length > 0) {
    lines.push(`### Cyclomatic Complexity Violations (> ${report.metrics.maxCyclomatic})`);
    lines.push('');
    lines.push('| File | Function | Cyclomatic | Cognitive | LOC |');
    lines.push('|---|---|---:|---:|---:|');
    for (const fn of report.metrics.cyclomaticViolations.slice(0, 20)) {
      lines.push(`| \`${escapeMd(fn.file)}\` | \`${escapeMd(fn.name)}\` | ${fn.cyclo} | ${fn.cognitive} | ${fn.loc} |`);
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

// ---------------------------------------------------------------------------
// Project variable validation (fail-closed)
// ---------------------------------------------------------------------------

const VALID_SCOPES = new Set(['pr', 'full']);
const VALID_ENFORCEMENTS = new Set(['report-only', 'standard', 'strict']);
const VALID_BOOLEANS = new Set(['true', 'false']);
const VALID_COVERAGE_MODES = new Set(['required', 'none']);
const SEMVER_RE = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const POLICY_REF_RE = /^[A-Za-z0-9._/-]+$/;
const ADVISORY_PLUGINS_RE = /^[A-Za-z0-9_,-]+$/;
const PERCENT_RE = /^(?:100(?:\.0{1,2})?|[0-9]{1,2}(?:\.[0-9]{1,2})?)$/;

export const REQUIRED_PROJECT_VARS = [
  { name: 'QLTY_SCOPE', accepted: '`pr` ou `full`', example: 'pr' },
  { name: 'QLTY_ENFORCEMENT', accepted: '`report-only`, `standard` ou `strict`', example: 'standard' },
  { name: 'QLTY_VERSION', accepted: 'SemVer sem `v`', example: '0.672.0' },
  { name: 'QLTY_POLICY_REF', accepted: 'Tag ou SHA em `joaovpimenta/joaovpimenta`', example: 'qlty-v0.3.0' },
  { name: 'QLTY_ENABLE_SMELLS', accepted: '`true` ou `false`', example: 'true' },
  { name: 'QLTY_ENABLE_METRICS', accepted: '`true` ou `false`', example: 'true' },
  { name: 'QLTY_MAX_CYCLOMATIC', accepted: 'Inteiro `1..100` ou `off`', example: '10' },
  { name: 'QLTY_COVERAGE_MODE', accepted: '`required` ou `none`', example: 'required' },
];

export const COVERAGE_REQUIRED_VARS = [
  { name: 'QLTY_MIN_COVERAGE_TOTAL', accepted: 'Número `0..100` (%)', example: '90' },
  { name: 'QLTY_MIN_COVERAGE_DIFF', accepted: 'Número `0..100` (%)', example: '90' },
  { name: 'QLTY_MIN_TESTS', accepted: 'Inteiro `>= 1`', example: '1' },
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
    problems.push('Variável obrigatória ausente: `QLTY_POLICY_REF` (esperado: tag ou SHA, ex.: `qlty-v0.3.0`).');
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

  const maxCyclomaticRaw = read('QLTY_MAX_CYCLOMATIC');
  let maxCyclomatic = null;
  if (!maxCyclomaticRaw) {
    problems.push('Variável obrigatória ausente: `QLTY_MAX_CYCLOMATIC` (esperado: inteiro `1..100` ou `off`).');
  } else if (maxCyclomaticRaw !== 'off') {
    if (!/^[0-9]+$/.test(maxCyclomaticRaw) || Number(maxCyclomaticRaw) < 1 || Number(maxCyclomaticRaw) > 100) {
      problems.push(`Valor inválido em \`QLTY_MAX_CYCLOMATIC\`: \`${maxCyclomaticRaw}\` (esperado: inteiro \`1..100\` ou \`off\`).`);
    } else {
      maxCyclomatic = Number(maxCyclomaticRaw);
      if (enableMetrics === 'false') {
        problems.push('Configuração inconsistente: `QLTY_MAX_CYCLOMATIC` ativo exige `QLTY_ENABLE_METRICS=true`.');
      }
    }
  }

  const coverageMode = read('QLTY_COVERAGE_MODE');
  if (!coverageMode) {
    problems.push('Variável obrigatória ausente: `QLTY_COVERAGE_MODE` (esperado: `required` ou `none`).');
  } else if (!VALID_COVERAGE_MODES.has(coverageMode)) {
    problems.push(`Valor inválido em \`QLTY_COVERAGE_MODE\`: \`${coverageMode}\` (esperado: \`required\` ou \`none\`).`);
  }

  let minCoverageTotal = null;
  let minCoverageDiff = null;
  let minTests = null;

  if (coverageMode === 'required') {
    const rawTotal = read('QLTY_MIN_COVERAGE_TOTAL');
    if (!rawTotal) {
      problems.push('Variável obrigatória ausente (com `QLTY_COVERAGE_MODE=required`): `QLTY_MIN_COVERAGE_TOTAL` (esperado: `0..100`, ex.: `90`).');
    } else if (!PERCENT_RE.test(rawTotal)) {
      problems.push(`Valor inválido em \`QLTY_MIN_COVERAGE_TOTAL\`: \`${rawTotal}\` (esperado: número \`0..100\`).`);
    } else {
      minCoverageTotal = Number(rawTotal);
    }

    const rawDiff = read('QLTY_MIN_COVERAGE_DIFF');
    if (!rawDiff) {
      problems.push('Variável obrigatória ausente (com `QLTY_COVERAGE_MODE=required`): `QLTY_MIN_COVERAGE_DIFF` (esperado: `0..100`, ex.: `90`).');
    } else if (!PERCENT_RE.test(rawDiff)) {
      problems.push(`Valor inválido em \`QLTY_MIN_COVERAGE_DIFF\`: \`${rawDiff}\` (esperado: número \`0..100\`).`);
    } else {
      minCoverageDiff = Number(rawDiff);
    }

    const rawMinTests = read('QLTY_MIN_TESTS');
    if (!rawMinTests) {
      problems.push('Variável obrigatória ausente (com `QLTY_COVERAGE_MODE=required`): `QLTY_MIN_TESTS` (esperado: inteiro `>= 1`, ex.: `1`).');
    } else if (!/^[0-9]+$/.test(rawMinTests) || Number(rawMinTests) < 1) {
      problems.push(`Valor inválido em \`QLTY_MIN_TESTS\`: \`${rawMinTests}\` (esperado: inteiro \`>= 1\`).`);
    } else {
      minTests = Number(rawMinTests);
    }
  }

  const rawBlockSmells = read('QLTY_BLOCK_SMELLS');
  const blockSmells = rawBlockSmells || 'false';
  if (rawBlockSmells && !VALID_BOOLEANS.has(rawBlockSmells)) {
    problems.push(`Valor inválido em \`QLTY_BLOCK_SMELLS\`: \`${rawBlockSmells}\` (esperado: \`true\` ou \`false\`).`);
  }

  const rawAllowSkipped = read('QLTY_ALLOW_SKIPPED_TESTS');
  const allowSkippedTests = rawAllowSkipped || 'true';
  if (rawAllowSkipped && !VALID_BOOLEANS.has(rawAllowSkipped)) {
    problems.push(`Valor inválido em \`QLTY_ALLOW_SKIPPED_TESTS\`: \`${rawAllowSkipped}\` (esperado: \`true\` ou \`false\`).`);
  }

  const rawDiffFailOnEmpty = read('QLTY_COVERAGE_DIFF_FAIL_ON_EMPTY');
  const diffFailOnEmpty = rawDiffFailOnEmpty || 'false';
  if (rawDiffFailOnEmpty && !VALID_BOOLEANS.has(rawDiffFailOnEmpty)) {
    problems.push(`Valor inválido em \`QLTY_COVERAGE_DIFF_FAIL_ON_EMPTY\`: \`${rawDiffFailOnEmpty}\` (esperado: \`true\` ou \`false\`).`);
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
          maxCyclomatic,
          coverageMode,
          minCoverageTotal,
          minCoverageDiff,
          minTests,
          blockSmells: blockSmells === 'true',
          allowSkippedTests: allowSkippedTests === 'true',
          diffFailOnEmpty: diffFailOnEmpty === 'true',
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
    '### Obrigatórias quando `QLTY_COVERAGE_MODE=required`',
    '',
    '| Variável | Valores aceitos | Exemplo |',
    '|---|---|---|',
    ...COVERAGE_REQUIRED_VARS.map((item) => `| \`${item.name}\` | ${item.accepted} | \`${item.example}\` |`),
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

function numEnv(name, fallback = null) {
  const raw = process.env[name];
  if (raw === undefined || raw === '' || raw === 'off') return fallback;
  const parsed = Number(raw);
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
  const coverageMode = requiredChoiceEnv('QUALITY_COVERAGE_MODE', VALID_COVERAGE_MODES, envErrors);

  const maxCyclomaticRaw = String(process.env.QUALITY_MAX_CYCLOMATIC ?? '').trim();
  if (!maxCyclomaticRaw) {
    envErrors.push('Variável obrigatória ausente na execução do gate: `QUALITY_MAX_CYCLOMATIC` (`1..100` ou `off`).');
  } else if (maxCyclomaticRaw !== 'off' && (!/^[0-9]+$/.test(maxCyclomaticRaw) || Number(maxCyclomaticRaw) < 1 || Number(maxCyclomaticRaw) > 100)) {
    envErrors.push(`Valor inválido em \`QUALITY_MAX_CYCLOMATIC\`: \`${maxCyclomaticRaw}\`.`);
  }

  const blockSmellsRaw = String(process.env.QUALITY_BLOCK_SMELLS ?? 'false').trim();
  if (!VALID_BOOLEANS.has(blockSmellsRaw)) {
    envErrors.push(`Valor inválido em \`QUALITY_BLOCK_SMELLS\`: \`${blockSmellsRaw}\`.`);
  }

  const allowSkippedRaw = String(process.env.QUALITY_ALLOW_SKIPPED_TESTS ?? 'true').trim();
  if (!VALID_BOOLEANS.has(allowSkippedRaw)) {
    envErrors.push(`Valor inválido em \`QUALITY_ALLOW_SKIPPED_TESTS\`: \`${allowSkippedRaw}\`.`);
  }

  const diffFailOnEmptyRaw = String(process.env.QUALITY_COVERAGE_DIFF_FAIL_ON_EMPTY ?? 'false').trim();
  if (!VALID_BOOLEANS.has(diffFailOnEmptyRaw)) {
    envErrors.push(`Valor inválido em \`QUALITY_COVERAGE_DIFF_FAIL_ON_EMPTY\`: \`${diffFailOnEmptyRaw}\`.`);
  }

  let minCoverageTotal = null;
  let minCoverageDiff = null;
  let minTests = null;
  if (coverageMode === 'required') {
    const rawTotal = String(process.env.QUALITY_MIN_COVERAGE_TOTAL ?? '').trim();
    const rawDiff = String(process.env.QUALITY_MIN_COVERAGE_DIFF ?? '').trim();
    const rawTests = String(process.env.QUALITY_MIN_TESTS ?? '').trim();
    if (!rawTotal || !PERCENT_RE.test(rawTotal)) {
      envErrors.push(`Variável obrigatória ausente ou inválida: \`QUALITY_MIN_COVERAGE_TOTAL\` (\`${rawTotal || 'vazio'}\`).`);
    } else {
      minCoverageTotal = Number(rawTotal);
    }
    if (!rawDiff || !PERCENT_RE.test(rawDiff)) {
      envErrors.push(`Variável obrigatória ausente ou inválida: \`QUALITY_MIN_COVERAGE_DIFF\` (\`${rawDiff || 'vazio'}\`).`);
    } else {
      minCoverageDiff = Number(rawDiff);
    }
    if (!rawTests || !/^[0-9]+$/.test(rawTests) || Number(rawTests) < 1) {
      envErrors.push(`Variável obrigatória ausente ou inválida: \`QUALITY_MIN_TESTS\` (\`${rawTests || 'vazio'}\`).`);
    } else {
      minTests = Number(rawTests);
    }
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

  const workspaceRoot = process.env.QUALITY_WORKSPACE_ROOT || process.env.GITHUB_WORKSPACE || '';
  const discovered = coverageMode === 'required'
    ? discoverTestReports(process.env.QUALITY_TEST_REPORTS_DIR || '', workspaceRoot)
    : { coverageReports: [], junitReports: [], coverageFiles: [], junitFiles: [] };

  const checkSarifRaw = readOptionalFile(process.env.QUALITY_CHECK_SARIF);
  const smellsSarifRaw = readOptionalFile(process.env.QUALITY_SMELLS_SARIF);
  const diffRaw = readOptionalFile(process.env.QUALITY_DIFF_FILE);

  const report = evaluateQualityGate({
    scope,
    enforcement,
    qltyVersion,
    baseRef: process.env.QUALITY_BASE_REF || null,
    advisoryPlugins: (process.env.QUALITY_ADVISORY_PLUGINS || '').split(','),
    blockSmells: blockSmellsRaw === 'true',
    maxCyclomatic: numEnv('QUALITY_MAX_CYCLOMATIC', null),
    coverageMode,
    minCoverageTotal,
    minCoverageDiff,
    minTests,
    allowSkippedTests: allowSkippedRaw === 'true',
    diffFailOnEmpty: diffFailOnEmptyRaw === 'true',
    workspaceRoot,
    coverageReports: discovered.coverageReports,
    junitReports: discovered.junitReports,
    diffRaw,
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
