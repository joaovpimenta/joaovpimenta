class SafeError extends Error {}

const token = required('GH_TOKEN');
const dryRun = boolEnv('DRY_RUN', false);
const triageLabel = 'policy:needs-triage';

const typeLabels = {
  Epic:'type:epic', Feature:'type:feature', Bug:'type:bug',
  Task:'type:task', 'Tech Debt':'type:tech-debt', Research:'type:research'
};
const areaLabels = {
  Frontend:'area:frontend', Backend:'area:backend', 'Design System':'area:design-system',
  Mobile:'area:mobile', Infra:'area:infra', Docs:'area:docs', Security:'area:security'
};

const plans = new Map();
function add(repo, number, type, areas) {
  plans.set(repo.toLowerCase() + '#' + number, { repo, number, type, areas });
}

const ds='Glucontinuum/glucontinuum-design-system';
[
[1,'Epic',['Design System']],[2,'Epic',['Design System','Infra','Docs','Security']],[3,'Epic',['Design System']],
[4,'Epic',['Design System']],[5,'Epic',['Design System','Frontend','Mobile']],[6,'Epic',['Design System','Frontend','Mobile']],
[7,'Epic',['Design System','Frontend']],[8,'Epic',['Design System','Mobile']],[9,'Epic',['Design System','Mobile']],
[10,'Epic',['Design System','Infra']],[11,'Epic',['Design System','Docs']],
[12,'Task',['Design System','Infra','Docs']],[13,'Task',['Design System','Docs']],[14,'Task',['Design System','Docs']],
[15,'Task',['Design System','Security','Infra']],[16,'Task',['Design System']],[17,'Task',['Design System']],
[18,'Task',['Design System']],[19,'Task',['Design System']],[20,'Task',['Design System']],[21,'Task',['Design System']],
[22,'Task',['Design System','Frontend','Mobile']],[23,'Task',['Design System','Mobile']],[24,'Task',['Design System']],
[25,'Task',['Design System']],[26,'Task',['Design System','Frontend']],[27,'Task',['Design System','Mobile']],
[28,'Task',['Design System','Mobile']],[29,'Task',['Design System','Frontend','Mobile','Infra']],[30,'Task',['Design System']],
[31,'Task',['Design System','Frontend','Mobile','Infra']],[32,'Task',['Design System','Frontend']],
[33,'Task',['Design System','Frontend']],[34,'Task',['Design System','Mobile']],[35,'Task',['Design System','Mobile']],
[36,'Task',['Design System','Mobile']],[37,'Task',['Design System','Mobile']],[38,'Task',['Design System','Infra']],
[39,'Task',['Design System','Infra','Docs']],[40,'Task',['Design System','Infra']],[41,'Task',['Design System','Docs']],
[42,'Task',['Design System','Infra']],[43,'Task',['Design System','Docs','Infra']]
].forEach(x=>add(ds,...x));

const watch='Glucontinuum/glucontinuum-watch';
[
[1,'Epic',['Mobile']],[2,'Task',['Mobile','Backend','Docs']],[3,'Feature',['Mobile','Backend','Security']],
[4,'Feature',['Mobile','Backend']],[5,'Feature',['Mobile','Frontend']],[6,'Feature',['Mobile']],
[7,'Feature',['Mobile','Backend']],[8,'Feature',['Mobile','Frontend']],[9,'Task',['Mobile','Infra']],
[10,'Task',['Mobile','Infra','Docs']],[22,'Feature',['Mobile','Backend']],[23,'Bug',['Mobile','Frontend','Design System']]
].forEach(x=>add(watch,...x));

const app='Glucontinuum/Glucontinuum';
[
[33,'Feature',['Mobile']],[34,'Feature',['Mobile','Frontend']],[35,'Feature',['Mobile','Frontend']],
[36,'Feature',['Mobile','Frontend']],[37,'Feature',['Mobile','Frontend']],[38,'Feature',['Mobile','Frontend']],
[39,'Feature',['Mobile']],[40,'Feature',['Mobile']],[41,'Feature',['Mobile']],[42,'Feature',['Mobile','Design System']],
[43,'Feature',['Mobile','Frontend']],[44,'Feature',['Mobile','Backend']],[45,'Feature',['Mobile','Backend']],
[46,'Feature',['Mobile','Frontend']],[47,'Feature',['Mobile','Frontend']],[48,'Task',['Infra']],
[50,'Epic',['Mobile']],[51,'Feature',['Mobile']],[52,'Feature',['Mobile','Backend']],[53,'Feature',['Mobile','Backend']],
[54,'Feature',['Mobile','Backend']],[55,'Feature',['Mobile','Backend','Design System']],[56,'Feature',['Mobile','Backend']],
[57,'Feature',['Mobile']],[58,'Task',['Mobile','Security','Infra']],[59,'Feature',['Mobile']],
[63,'Tech Debt',['Mobile','Frontend']],[72,'Research',['Mobile','Infra']],[73,'Epic',['Mobile','Backend']],
[75,'Feature',['Mobile','Backend','Security']],[76,'Feature',['Mobile','Backend']],[77,'Feature',['Mobile','Backend']],
[78,'Feature',['Mobile','Backend']],[79,'Tech Debt',['Mobile','Backend']],[83,'Feature',['Mobile','Backend']]
].forEach(x=>add(app,...x));

const poke='joaovpimenta/pokemon-story-hub';
[
[2,'Task',['Docs']],[5,'Task',['Docs']],[6,'Feature',['Frontend','Mobile']],[9,'Bug',['Infra','Mobile']],
[37,'Feature',['Frontend','Mobile']],[38,'Bug',['Frontend','Backend','Mobile']],[39,'Research',['Backend']],
[40,'Epic',['Frontend','Mobile']],[42,'Feature',['Frontend','Mobile']],[43,'Feature',['Frontend','Mobile']],
[44,'Feature',['Frontend','Mobile']],[45,'Feature',['Frontend','Mobile']],[46,'Feature',['Frontend','Mobile']],
[68,'Tech Debt',['Mobile','Frontend','Backend']],[71,'Feature',['Frontend','Mobile']],
[72,'Epic',['Mobile','Frontend','Backend']],[73,'Tech Debt',['Mobile','Backend']],[74,'Tech Debt',['Mobile','Backend']],
[75,'Tech Debt',['Frontend','Mobile']],[76,'Tech Debt',['Frontend','Mobile']],[77,'Tech Debt',['Frontend','Mobile']],
[78,'Tech Debt',['Frontend','Mobile']],[79,'Tech Debt',['Frontend','Mobile']],[80,'Tech Debt',['Frontend','Mobile']],
[81,'Tech Debt',['Frontend','Mobile']],[82,'Tech Debt',['Frontend','Mobile']],[83,'Tech Debt',['Mobile','Backend']],
[84,'Bug',['Frontend','Mobile']],[88,'Research',['Backend']],[89,'Feature',['Backend']],
[91,'Feature',['Backend']],[92,'Feature',['Backend']]
].forEach(x=>add(poke,...x));

const counters={planned:plans.size,fetched:0,updated:0,alreadyCompliant:0,missing:0,errors:0};

for (const plan of plans.values()) {
  try {
    const issue=await rest('/repos/'+plan.repo+'/issues/'+plan.number);
    counters.fetched++;
    if (!issue || issue.pull_request) { counters.missing++; continue; }

    const desiredType=typeLabels[plan.type];
    const desiredAreas=plan.areas.map(x=>areaLabels[x]);
    if (!desiredType || desiredAreas.some(x=>!x)) throw new SafeError('Unknown taxonomy value.');

    const current=(issue.labels||[]).map(x=>typeof x==='string'?x:x.name).filter(Boolean);
    const preserved=current.filter(label=>label!==triageLabel && !label.startsWith('type:') && !label.startsWith('area:'));
    const desired=[...new Set([...preserved,desiredType,...desiredAreas])];

    if (sameSet(current,desired)) { counters.alreadyCompliant++; continue; }
    if (!dryRun) {
      await rest('/repos/'+plan.repo+'/issues/'+plan.number+'/labels',{method:'PUT',body:{labels:desired}});
    }
    counters.updated++;
  } catch (error) {
    counters.errors++;
    safeError('Issue classification failed',error);
  }
}

console.log('Issue Classification Retrofit');
for (const [k,v] of Object.entries(counters)) console.log(k+': '+v);
console.log('Mode: '+(dryRun?'DRY RUN':'APPLY'));
if (counters.errors>0) process.exitCode=1;

async function rest(path,options={}) {
  const response=await fetch('https://api.github.com'+path,{
    method:options.method||'GET',
    headers:{
      authorization:'Bearer '+token,
      accept:'application/vnd.github+json',
      'content-type':'application/json',
      'x-github-api-version':'2026-03-10',
      'user-agent':'development-hq-issue-classification'
    },
    body:options.body?JSON.stringify(options.body):undefined
  });
  if (!response.ok) {
    const error=new SafeError('GitHub REST request failed ('+response.status+').');
    error.status=response.status;
    throw error;
  }
  if (response.status===204) return null;
  return response.json();
}
function safeError(prefix,error) {
  const message=error instanceof SafeError?error.message:'Unexpected error (details intentionally suppressed).';
  console.error(prefix+': '+message);
}
function sameSet(a,b) {
  const x=new Set(a), y=new Set(b);
  return x.size===y.size && [...x].every(v=>y.has(v));
}
function env(name,fallback='') { return String(process.env[name]??fallback).trim(); }
function required(name) { const value=env(name); if (!value) throw new Error('Missing '+name); return value; }
function boolEnv(name,fallback) { const value=env(name); return value?['1','true','yes','on'].includes(value.toLowerCase()):fallback; }
