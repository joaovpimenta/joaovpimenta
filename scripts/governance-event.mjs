import fs from 'node:fs';

const token = required('GH_TOKEN');
const repository = required('GITHUB_REPOSITORY');
const eventPath = required('GITHUB_EVENT_PATH');
const policyPath = env('GOVERNANCE_POLICY_PATH', '/tmp/taxonomy.json');

const event = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
const policy = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
const issue = event.issue;

if (!issue || issue.pull_request) {
  console.log('Governance event: nothing to reconcile');
  process.exit(0);
}

const typeDefs = policy.type || [];
const areaDefs = policy.area || [];
const triageLabel = policy.rules?.unknownMetadataLabel || 'policy:needs-triage';
const managedLabels = new Set([
  ...typeDefs.map(x => x.label),
  ...areaDefs.map(x => x.label),
  ...(policy.policyLabels || []).map(x => x.label)
]);

const currentLabels = (issue.labels || []).map(x => typeof x === 'string' ? x : x.name).filter(Boolean);
const currentTypes = currentLabels.filter(x => typeDefs.some(d => eq(d.label, x)));
const currentAreas = currentLabels.filter(x => areaDefs.some(d => eq(d.label, x)));

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

const desiredLabels = [
  ...currentLabels.filter(x => !managedLabels.has(x)),
  ...desiredManaged
];

if (sameSet(currentLabels, desiredLabels)) {
  console.log('Governance event: already compliant');
  process.exit(0);
}

await api(`/repos/${repository}/issues/${issue.number}/labels`, {
  method: 'PUT',
  body: { labels: desiredLabels }
});

console.log('Governance event: metadata reconciled');
console.log(`Type valid: ${Boolean(selectedType)}`);
console.log(`Area count: ${selectedAreas.length}`);
console.log(`Needs triage: ${!valid}`);

function resolveSingle(section, defs, current) {
  if (section.present) {
    const values = parseValues(section.value);
    const match = defs.find(d => values.some(v => eq(v, d.value) || eq(v, d.label)));
    return match || null;
  }
  if (current.length === 1) {
    return defs.find(d => eq(d.label, current[0])) || null;
  }
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

function sameSet(a, b) {
  const x = new Set(a);
  const y = new Set(b);
  return x.size === y.size && [...x].every(v => y.has(v));
}

function eq(a, b) {
  return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}

async function api(path, options = {}) {
  const response = await fetch(`https://api.github.com${path}`, {
    method: options.method || 'GET',
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
      'x-github-api-version': '2026-03-10',
      'user-agent': 'development-hq-governance-event'
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  if (!response.ok) throw new Error(`GitHub API request failed (${response.status})`);
  if (response.status === 204) return null;
  return response.json();
}

function env(name, fallback = '') {
  return String(process.env[name] ?? fallback).trim();
}
function required(name) {
  const value = env(name);
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}
