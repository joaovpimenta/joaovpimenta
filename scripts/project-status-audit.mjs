const token = process.env.GH_TOKEN;
const owner = process.env.PROJECT_OWNER || 'joaovpimenta';
const number = Number(process.env.PROJECT_NUMBER || '2');

if (!token) throw new Error('Missing GH_TOKEN');

const query = `query($login:String!,$number:Int!,$after:String){
  user(login:$login){
    projectV2(number:$number){
      title
      items(first:100,after:$after){
        pageInfo{hasNextPage endCursor}
        nodes{
          id
          updatedAt
          fieldValueByName(name:"Status"){
            ... on ProjectV2ItemFieldSingleSelectValue { name }
          }
          content{
            __typename
            ... on Issue{
              number
              state
              title
              url
              updatedAt
              repository{nameWithOwner}
            }
            ... on PullRequest{
              number
              state
              merged
              mergedAt
              isDraft
              title
              url
              updatedAt
              repository{nameWithOwner}
            }
          }
        }
      }
    }
  }
}`;

let after = null;
const items = [];
let projectTitle = null;
do {
  const response = await fetch('https://api.github.com/graphql', {
    method:'POST',
    headers:{
      authorization:'Bearer '+token,
      accept:'application/vnd.github+json',
      'content-type':'application/json',
      'x-github-api-version':'2026-03-10',
      'user-agent':'development-hq-status-audit'
    },
    body:JSON.stringify({query,variables:{login:owner,number,after}})
  });
  const json = await response.json();
  if (!response.ok || json.errors?.length) {
    const messages=(json.errors||[]).map(e=>String(e.message||'unknown')).join(' | ');
    throw new Error('Project GraphQL audit failed: '+(messages||('HTTP '+response.status)));
  }
  const project=json.data.user?.projectV2;
  if (!project) throw new Error('Project not found');
  projectTitle=project.title;
  items.push(...project.items.nodes);
  after=project.items.pageInfo.hasNextPage?project.items.pageInfo.endCursor:null;
} while(after);

const counts={};
const definitive=[];
const questionable=[];
for(const item of items){
  const status=item.fieldValueByName?.name || null;
  counts[status || '(unset)']=(counts[status || '(unset)']||0)+1;
  const c=item.content;
  if(!c) continue;

  const closed = c.__typename==='Issue'
    ? c.state==='CLOSED'
    : c.__typename==='PullRequest'
      ? (c.merged===true || c.state==='CLOSED' || c.state==='MERGED')
      : false;
  const open = c.__typename==='Issue'
    ? c.state==='OPEN'
    : c.__typename==='PullRequest'
      ? (c.state==='OPEN' && !c.merged)
      : false;

  if(closed && status!=='Done'){
    definitive.push({kind:'closed-not-done',type:c.__typename,repo:c.repository?.nameWithOwner,number:c.number,status,url:c.url});
  }
  if(open && status==='Done'){
    definitive.push({kind:'open-marked-done',type:c.__typename,repo:c.repository?.nameWithOwner,number:c.number,status,url:c.url});
  }
  if(!status){
    definitive.push({kind:'missing-status',type:c.__typename,repo:c.repository?.nameWithOwner,number:c.number,status,url:c.url});
  }

  if(c.__typename==='PullRequest' && open && c.isDraft && status==='Review'){
    questionable.push({kind:'draft-pr-in-review',repo:c.repository?.nameWithOwner,number:c.number,status,url:c.url});
  }
}

console.log('Project Status Reality Audit');
console.log('Project: '+projectTitle);
console.log('Items scanned: '+items.length);
for(const [status,count] of Object.entries(counts).sort()) console.log('Status '+status+': '+count);
console.log('Definitive mismatches: '+definitive.length);
for(const x of definitive) console.log('MISMATCH '+x.kind+' | '+x.type+' | '+x.repo+'#'+x.number+' | status='+(x.status||'(unset)'));
console.log('Questionable states: '+questionable.length);
for(const x of questionable) console.log('CHECK '+x.kind+' | '+x.repo+'#'+x.number+' | status='+x.status);
