import fs from 'node:fs';

class SafeError extends Error {}

const token = required('GH_TOKEN');
const owner = env('PROJECT_OWNER', 'joaovpimenta');
const projectNumber = intEnv('PROJECT_NUMBER', 2, 1, 1000000);
const dryRun = boolEnv('DRY_RUN', false);
const policy = JSON.parse(fs.readFileSync('governance/taxonomy.json', 'utf8'));

process.stdout.write(`::add-mask::${token}\n`);

const counters = {
  fieldsWouldCreate: 0,
  fieldsCreated: 0,
  fieldsUpdated: 0,
  itemsScanned: 0,
  fieldValuesWouldUpdate: 0,
  fieldValuesUpdated: 0,
  viewsWouldCreate: 0,
  viewsCreated: 0,
  errors: 0
};

try {
  const project = await getProject();
  const items = await listProjectItems(project.id);

  const organizations = unique(
    items.map(item => item.content?.repository?.owner?.login).filter(Boolean)
  );
  const products = unique(
    items.map(item => item.content?.repository?.nameWithOwner).filter(Boolean)
  );

  await ensureProjectFields(project, organizations, products);

  if (!dryRun) {
    // Re-fetch fields after creation/update so option IDs are current.
    Object.assign(project, await getProject());
  }

  const fieldMap = new Map((project.fields?.nodes || []).map(field => [field.name, field]));

  for (const item of items) {
    if (!item.content?.repository) continue;
    counters.itemsScanned++;

    try {
      await reconcileItem(project.id, item, fieldMap);
    } catch (error) {
      counters.errors++;
      safeError('Project item reconciliation failed', error);
    }
  }

  if (!dryRun) {
    await pruneKnownLegacyStatusOptions(project);
  }

  await ensureViews(project);
} catch (error) {
  counters.errors++;
  safeError('Project governance failed', error);
  process.exitCode = 1;
} finally {
  console.log('Development HQ Project Governance');
  console.log(`Fields would create: ${counters.fieldsWouldCreate}`);
  console.log(`Fields created: ${counters.fieldsCreated}`);
  console.log(`Fields updated: ${counters.fieldsUpdated}`);
  console.log(`Items scanned: ${counters.itemsScanned}`);
  console.log(`Field values would update: ${counters.fieldValuesWouldUpdate}`);
  console.log(`Field values updated: ${counters.fieldValuesUpdated}`);
  console.log(`Views would create: ${counters.viewsWouldCreate}`);
  console.log(`Views created: ${counters.viewsCreated}`);
  console.log(`Errors: ${counters.errors}`);
  console.log(`Mode: ${dryRun ? 'DRY RUN' : 'APPLY'}`);
}

async function getProject() {
  const data = await graphql(`
    query($login:String!,$number:Int!){
      user(login:$login){
        projectV2(number:$number){
          id
          title
          fields(first:100){
            nodes{
              __typename
              ... on ProjectV2Field { id name dataType databaseId }
              ... on ProjectV2SingleSelectField {
                id name dataType databaseId
                options { id name color description }
              }
              ... on ProjectV2MultiSelectField {
                id name dataType databaseId
                multiSelectOptions { id name color description }
              }
            }
          }
        }
      }
    }`,
    { login: owner, number: projectNumber }
  );

  const project = data.user?.projectV2;
  if (!project) throw new SafeError('Configured Project was not found or token cannot access it.');
  return project;
}

async function listProjectItems(projectId) {
  const out = [];
  let after = null;

  for (let page = 1; page <= 500; page++) {
    const data = await graphql(`
      query($id:ID!,$after:String){
        node(id:$id){
          ... on ProjectV2 {
            items(first:100,after:$after){
              nodes{
                id
                content{
                  __typename
                  ... on Issue {
                    id number state
                    repository { nameWithOwner name owner { login } }
                    labels(first:50){ nodes { name } }
                  }
                  ... on PullRequest {
                    id number state isDraft mergedAt
                    repository { nameWithOwner name owner { login } }
                    labels(first:50){ nodes { name } }
                  }
                }
                fieldValues(first:50){
                  nodes{
                    __typename
                    ... on ProjectV2ItemFieldSingleSelectValue {
                      name optionId
                      field { ... on ProjectV2FieldCommon { name } }
                    }
                    ... on ProjectV2ItemFieldMultiSelectValue {
                      value
                      options { id name }
                      field { ... on ProjectV2FieldCommon { name } }
                    }
                  }
                }
              }
              pageInfo { hasNextPage endCursor }
            }
          }
        }
      }`,
      { id: projectId, after }
    );

    const conn = data.node?.items;
    if (!conn) throw new SafeError('Project items could not be read.');
    out.push(...(conn.nodes || []));

    if (!conn.pageInfo?.hasNextPage) break;
    after = conn.pageInfo.endCursor;
    if (!after) break;
  }

  return out;
}

async function ensureProjectFields(project, organizations, products) {
  const current = new Map((project.fields?.nodes || []).map(field => [field.name, field]));

  await ensureField(project.id, current.get('Type'), {
    name: 'Type',
    type: 'SINGLE_SELECT',
    options: (policy.type || []).map((x, i) => option(x.value, projectColor(i), x.description))
  });

  await ensureField(project.id, current.get('Area'), {
    name: 'Area',
    type: 'MULTI_SELECT',
    options: (policy.area || []).map((x, i) => option(x.value, projectColor(i), x.description))
  });

  await ensureField(project.id, current.get('Priority'), {
    name: 'Priority',
    type: 'SINGLE_SELECT',
    options: (policy.priority || []).map(x => option(x.value, x.color, x.description))
  });

  await ensureField(project.id, current.get('Organization'), {
    name: 'Organization',
    type: 'SINGLE_SELECT',
    options: organizations.sort().map((x, i) => option(x, projectColor(i), 'Repository owner'))
  });

  await ensureField(project.id, current.get('Product'), {
    name: 'Product',
    type: 'SINGLE_SELECT',
    options: products.sort().map((x, i) => option(x, projectColor(i), 'Derived from repository'))
  });

  await ensureField(project.id, current.get('Status'), {
    name: 'Status',
    type: 'SINGLE_SELECT',
    options: (policy.status || []).map(x => option(x.value, x.color, x.description)),
    preserveExistingOptions: true
  });
}

async function ensureField(projectId, field, desired) {
  if (!field) {
    counters.fieldsWouldCreate++;
    if (dryRun) return;

    const args = {
      projectId,
      name: desired.name,
      dataType: desired.type
    };
    if (desired.type === 'SINGLE_SELECT') args.singleSelectOptions = desired.options;
    if (desired.type === 'MULTI_SELECT') args.multiSelectOptions = desired.options;

    await graphql(`
      mutation($input:CreateProjectV2FieldInput!){
        createProjectV2Field(input:$input){
          projectV2Field { ... on ProjectV2FieldCommon { id name } }
        }
      }`,
      { input: args }
    );
    counters.fieldsCreated++;
    return;
  }

  const actualType = field.__typename === 'ProjectV2MultiSelectField'
    ? 'MULTI_SELECT'
    : field.__typename === 'ProjectV2SingleSelectField'
      ? 'SINGLE_SELECT'
      : field.dataType;

  if (actualType !== desired.type) {
    throw new SafeError(`Project field type mismatch for ${desired.name}.`);
  }

  const currentOptions = desired.type === 'MULTI_SELECT'
    ? (field.multiSelectOptions || [])
    : (field.options || []);

  const desiredByName = new Map(desired.options.map(x => [x.name.toLowerCase(), x]));
  const merged = [];

  for (const existing of currentOptions) {
    const wanted = desiredByName.get(existing.name.toLowerCase());
    if (wanted) {
      merged.push({ ...wanted, id: existing.id });
      desiredByName.delete(existing.name.toLowerCase());
    } else if (desired.preserveExistingOptions) {
      merged.push({
        id: existing.id,
        name: existing.name,
        color: existing.color,
        description: existing.description || ''
      });
    }
  }

  merged.push(...desiredByName.values());

  const differs =
    merged.length !== currentOptions.length ||
    merged.some((x, i) => {
      const y = currentOptions[i];
      return !y ||
        x.name !== y.name ||
        x.color !== y.color ||
        String(x.description || '') !== String(y.description || '');
    });

  if (!differs) return;

  counters.fieldsUpdated++;
  if (dryRun) return;

  const input = { fieldId: field.id };
  if (desired.type === 'SINGLE_SELECT') input.singleSelectOptions = merged;
  if (desired.type === 'MULTI_SELECT') input.multiSelectOptions = merged;

  await graphql(`
    mutation($input:UpdateProjectV2FieldInput!){
      updateProjectV2Field(input:$input){
        projectV2Field { ... on ProjectV2FieldCommon { id name } }
      }
    }`,
    { input }
  );
}

async function reconcileItem(projectId, item, fields) {
  const content = item.content;
  const labels = new Set((content.labels?.nodes || []).map(x => x.name));
  const currentValues = new Map();

  for (const value of item.fieldValues?.nodes || []) {
    const fieldName = value.field?.name;
    if (!fieldName) continue;
    currentValues.set(fieldName, value);
  }

  const org = content.repository.owner?.login;
  const product = content.repository.nameWithOwner;

  if (org) await setSingle(projectId, item.id, fields.get('Organization'), org, currentValues.get('Organization'));
  if (product) await setSingle(projectId, item.id, fields.get('Product'), product, currentValues.get('Product'));

  const types = (policy.type || []).filter(x => labels.has(x.label));
  if (types.length === 1) {
    await setSingle(projectId, item.id, fields.get('Type'), types[0].value, currentValues.get('Type'));
  }

  const areas = (policy.area || []).filter(x => labels.has(x.label)).map(x => x.value);
  if (areas.length) {
    await setMulti(projectId, item.id, fields.get('Area'), areas, currentValues.get('Area'));
  }

  const currentStatus = currentValues.get('Status')?.name || null;
  const closed = content.state === 'CLOSED' || Boolean(content.mergedAt);
  let desiredStatus = currentStatus;

  if (closed) desiredStatus = 'Done';
  else if (!currentStatus || currentStatus === 'Todo') desiredStatus = 'Inbox';
  else if (currentStatus === 'In progress') desiredStatus = 'In Progress';

  if (desiredStatus) {
    await setSingle(projectId, item.id, fields.get('Status'), desiredStatus, currentValues.get('Status'));
  }
}

async function setSingle(projectId, itemId, field, desiredName, current) {
  if (!field || field.__typename !== 'ProjectV2SingleSelectField') return;
  if (current?.name === desiredName) return;

  const optionValue = (field.options || []).find(x => x.name === desiredName);
  if (!optionValue) return;

  counters.fieldValuesWouldUpdate++;
  if (dryRun) return;

  await graphql(`
    mutation($project:ID!,$item:ID!,$field:ID!,$option:String!){
      updateProjectV2ItemFieldValue(input:{
        projectId:$project,
        itemId:$item,
        fieldId:$field,
        value:{singleSelectOptionId:$option}
      }){ projectV2Item { id } }
    }`,
    { project: projectId, item: itemId, field: field.id, option: optionValue.id }
  );
  counters.fieldValuesUpdated++;
}

async function setMulti(projectId, itemId, field, desiredNames, current) {
  if (!field || field.__typename !== 'ProjectV2MultiSelectField') return;

  const optionMap = new Map((field.multiSelectOptions || []).map(x => [x.name, x.id]));
  const desiredIds = desiredNames.map(name => optionMap.get(name)).filter(Boolean).sort();
  const currentIds = (current?.options || []).map(x => x.id).filter(Boolean).sort();

  if (!desiredIds.length || arraysEqual(desiredIds, currentIds)) return;

  counters.fieldValuesWouldUpdate++;
  if (dryRun) return;

  await graphql(`
    mutation($project:ID!,$item:ID!,$field:ID!,$options:[String!]!){
      updateProjectV2ItemFieldValue(input:{
        projectId:$project,
        itemId:$item,
        fieldId:$field,
        value:{multiSelectOptionIds:$options}
      }){ projectV2Item { id } }
    }`,
    { project: projectId, item: itemId, field: field.id, options: desiredIds }
  );
  counters.fieldValuesUpdated++;
}

async function pruneKnownLegacyStatusOptions(project) {
  const refreshed = await getProject();
  const status = (refreshed.fields?.nodes || []).find(x => x.name === 'Status');
  if (!status || status.__typename !== 'ProjectV2SingleSelectField') return;

  const legacy = new Set(['Todo', 'In progress']);
  const cleaned = (status.options || [])
    .filter(x => !legacy.has(x.name))
    .map(x => ({
      id: x.id,
      name: x.name,
      color: x.color,
      description: x.description || ''
    }));

  if (cleaned.length === (status.options || []).length) return;

  await graphql(`
    mutation($input:UpdateProjectV2FieldInput!){
      updateProjectV2Field(input:$input){
        projectV2Field { ... on ProjectV2FieldCommon { id name } }
      }
    }`,
    { input: { fieldId: status.id, singleSelectOptions: cleaned } }
  );
  counters.fieldsUpdated++;
}


async function ensureViews(project) {
  const fields = new Map((project.fields?.nodes || []).map(field => [field.name, field]));
  const title = fields.get('Title')?.databaseId;
  const status = fields.get('Status')?.databaseId;
  const priority = fields.get('Priority')?.databaseId;
  const organization = fields.get('Organization')?.databaseId;
  const repository = fields.get('Repository')?.databaseId;
  const type = fields.get('Type')?.databaseId;
  const area = fields.get('Area')?.databaseId;
  const product = fields.get('Product')?.databaseId;
  const updated = fields.get('Updated')?.databaseId;

  const user = await rest(`/users/${encodeURIComponent(owner)}`);
  const viewsResponse = await rest(`/users/${user.id}/projectsV2/${projectNumber}/views?per_page=100`);
  const existing = Array.isArray(viewsResponse) ? viewsResponse : (viewsResponse.value || viewsResponse.views || []);
  const names = new Set(existing.map(view => view.name));

  const commonVisible = [title, status, priority, type, area, organization, product, repository].filter(Number.isInteger);
  const tableVisible = [...commonVisible, updated].filter(Number.isInteger);

  const specs = [
    {
      name: 'Command Center',
      layout: 'board',
      filter: 'is:open',
      visible_fields: commonVisible,
      sort_by: priority ? [[priority, 'asc']] : undefined,
      group_by: organization ? [organization] : undefined,
      vertical_group_by: status ? [status] : undefined
    },
    {
      name: 'By Repository',
      layout: 'table',
      filter: 'is:open',
      visible_fields: tableVisible,
      sort_by: priority ? [[priority, 'asc']] : undefined,
      group_by: repository ? [repository] : undefined
    },
    {
      name: 'Now',
      layout: 'board',
      filter: 'status:Ready,"In Progress",Review,Blocked',
      visible_fields: commonVisible,
      sort_by: priority ? [[priority, 'asc']] : undefined,
      group_by: organization ? [organization] : undefined,
      vertical_group_by: status ? [status] : undefined
    },
    {
      name: 'Triage',
      layout: 'table',
      filter: 'label:"policy:needs-triage"',
      visible_fields: tableVisible,
      sort_by: priority ? [[priority, 'asc']] : undefined,
      group_by: repository ? [repository] : undefined
    },
    {
      name: 'Pull Requests',
      layout: 'table',
      filter: 'is:pr is:open',
      visible_fields: tableVisible,
      sort_by: priority ? [[priority, 'asc']] : undefined,
      group_by: repository ? [repository] : undefined
    },
    {
      name: 'Recently Done',
      layout: 'table',
      filter: 'status:Done',
      visible_fields: tableVisible,
      sort_by: updated ? [[updated, 'desc']] : undefined,
      group_by: repository ? [repository] : undefined
    }
  ];

  for (const spec of specs) {
    if (names.has(spec.name)) continue;
    counters.viewsWouldCreate++;
    if (dryRun) continue;

    const body = Object.fromEntries(
      Object.entries(spec).filter(([, value]) => value !== undefined && (!Array.isArray(value) || value.length))
    );
    await rest(`/users/${user.id}/projectsV2/${projectNumber}/views`, { method: 'POST', body });
    counters.viewsCreated++;
  }
}

async function rest(path, options = {}) {
  const response = await fetch(`https://api.github.com${path}`, {
    method: options.method || 'GET',
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
      'x-github-api-version': '2026-03-10',
      'user-agent': 'development-hq-project-governance'
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  if (!response.ok) throw new SafeError(`GitHub REST request failed (${response.status}).`);
  if (response.status === 204) return null;
  return response.json();
}

function option(name, color, description = '') {
  return { name, color, description };
}

function projectColor(index) {
  return ['BLUE','GREEN','PURPLE','ORANGE','PINK','YELLOW','RED','GRAY'][index % 8];
}

async function graphql(query, variables) {
  const response = await fetch('https://api.github.com/graphql', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
      'x-github-api-version': '2026-03-10',
      'user-agent': 'development-hq-project-governance'
    },
    body: JSON.stringify({ query, variables })
  });

  if (!response.ok) throw new SafeError(`GitHub GraphQL request failed (${response.status}).`);
  const data = await response.json();
  if (data.errors?.length) throw new SafeError('GitHub GraphQL operation was rejected.');
  return data.data;
}

function safeError(prefix, error) {
  const message = error instanceof SafeError ? error.message : 'Unexpected error (details intentionally suppressed).';
  console.error(`${prefix}: ${message}`);
}
function arraysEqual(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
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
