/* All public exercises are constrained browser models. No submitted input is executed. */
'use strict';
const main = document.querySelector('main');
const scenarios = window.SCENARIOS;
const state = {view:'lab',scenario:'idor',completed:new Set(),mode:'vulnerable',account:'alice',reports:null,reportError:null};
const esc = v => String(v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pretty = v => typeof v === 'string' ? v : JSON.stringify(v,null,2);
const $ = selector => document.querySelector(selector);
const selected = () => scenarios.find(s=>s.id===state.scenario);
function renderHeader(title,description){return `<div class="topline"><span class="breadcrumb">SECUREFLOW / ${esc(state.view.toUpperCase())}</span><span class="badge">SAFE BROWSER SIMULATION</span></div><div class="page-title"><div><h1>${title}</h1><p class="lede">${description}</p></div>${state.view==='lab'?`<div class="progress-label">${state.completed.size} / 6 explored<div class="progress-track"><i style="width:${state.completed.size/6*100}%"></i></div></div>`:''}</div>`;}
function render(){
 document.querySelectorAll('[data-view]').forEach(a=>{a.classList.toggle('active',a.dataset.view===state.view);a.toggleAttribute('aria-current',a.dataset.view===state.view);});
 if(state.view==='lab') renderLab();
 else if(state.view==='pipeline') renderPipeline();
 else if(state.view==='shop') renderShop();
 else renderGuide();
}
function renderLab(){
 const s=selected();
 main.innerHTML=renderHeader('Find the flaw. Prove the fix.','Send the same input to two versions of a tiny shop, then inspect the code and detection limits.')+`
 <div class="lab-grid"><nav class="scenario-menu" aria-label="Security exercises">${scenarios.map((x,i)=>`<button class="scenario-button ${x.id===s.id?'active':''}" data-scenario="${x.id}" aria-pressed="${x.id===s.id}"><span class="scenario-number">${String(i+1).padStart(2,'0')}</span><span><strong>${esc(x.title)}</strong><small>${esc(x.tag.split(' · ')[0])}${state.completed.has(x.id)?' · explored':''}</small></span></button>`).join('')}</nav>
 <div class="workbench"><section class="panel"><div class="panel-heading"><h2>${esc(s.title)}</h2><span class="eyebrow">${esc(s.tag.split(' · ')[0])}</span></div><div class="panel-body"><div class="context">${s.context}</div><p class="scenario-summary">${esc(s.summary)}</p>
 <form id="exercise"><label class="request-label" for="payload">${esc(s.label)}</label><div class="request-row"><div class="request-editor"><span class="http-method">${esc(s.method)}</span><input id="payload" name="payload" value="${esc(s.initial)}" maxlength="300" autocomplete="off" spellcheck="false" ${['race','sca'].includes(s.id)?'readonly':''}></div><button class="primary" type="submit">${s.id==='sca'?'Compare versions':'Run comparison'}</button></div></form>
 <div class="hint-row">${s.id==='sca'?'Recorded pins':'Try an example'} ${(s.id==='sca'?[]:s.presets).map(p=>`<button class="preset" data-preset="${esc(p)}">${esc(p.trim())}</button>`).join('')}</div></div>
 <div class="response-grid" aria-live="polite" aria-atomic="true"><div class="response"><div class="response-head"><span class="label">${s.id==='sca'?'Older dependency':'Vulnerable version'}</span><span class="status" id="v-status">READY</span></div><pre id="v-result" class="placeholder">${s.id==='sca'?'Compare the recorded dependency audit.':'Submit the request to inspect its response.'}</pre><p class="result-note" id="v-note"></p></div><div class="response"><div class="response-head"><span class="label">${s.id==='sca'?'Comparison dependency':'Fixed version'}</span><span class="status" id="f-status">READY</span></div><pre id="f-result" class="placeholder">The same input is used for both versions.</pre><p class="result-note" id="f-note"></p></div></div>
 <div class="simulation-note">${s.id==='sca'?'Recorded audit evidence, with run time on the Scan evidence page.':'Browser simulation using fake data. This page sends no lab HTTP requests. Run the separate loopback Python lab for real sessions and responses.'}</div></section>
 <section class="panel"><div class="panel-heading"><h2>Where the bug lives</h2><span class="eyebrow">CODE REVIEW</span></div><div class="panel-body"><p class="root-cause"><strong>Root cause.</strong> ${esc(s.cause)}</p><div class="code-grid"><div class="code-card"><div class="code-label">VULNERABLE</div><pre>${esc(s.vulnerable)}</pre></div><div class="code-card"><div class="code-label fixed">REMEDIATED</div><pre>${esc(s.fixed)}</pre></div></div><p class="remediation">${esc(s.fix)}</p><div class="source-detail">${esc(s.file)} · shortened excerpts</div></div></section>
 <section class="panel"><div class="panel-heading"><h2>Which checks help?</h2></div><div class="panel-body"><div class="coverage">${s.coverage.map(c=>`<div class="coverage-item"><b>${c[0]}</b><div class="coverage-state">${esc(c[1])}</div><p>${esc(c[2])}</p></div>`).join('')}</div><div class="key-takeaway"><strong>Remember:</strong> ${esc(s.takeaway)}</div></div></section></div></div><div class="footer-line"><span>6 exercises · source-level fixes · targeted regression tests</span><span>V1 / WEB APPLICATION SECURITY</span></div>`;
 document.querySelectorAll('[data-scenario]').forEach(b=>b.onclick=()=>{state.scenario=b.dataset.scenario;renderLab();});
 document.querySelectorAll('[data-preset]').forEach(b=>b.onclick=()=>{$('#payload').value=b.dataset.preset;$('#payload').focus();});
 $('#exercise').onsubmit=e=>{e.preventDefault();runComparison($('#payload').value);};
}
function simulate(id,value){
 let v,f,vs,fs,vn,fn;
 if(id==='idor'){
  const data={'1001':{id:1001,owner_id:'alice',item:'Studio headphones',total:89},'1002':{id:1002,owner_id:'bob',item:'Mechanical keyboard',total:129}};
  const order=data[value.trim()];
  const valid=/^\d+$/.test(value.trim());
  vs=!valid?'400 BAD REQUEST':order?'200 OK':'404 NOT FOUND';
  fs=!valid?'400 BAD REQUEST':!order?'404 NOT FOUND':order.owner_id==='alice'?'200 OK':'403 FORBIDDEN';
  v=!valid?{error:'Order ID must be an integer'}:order||{error:'Order not found'};
  f=fs==='403 FORBIDDEN'?{error:'This order belongs to another account'}:v;
  vn=order?.owner_id==='bob'?'Alice receives Bob’s order. Ownership was not checked.':'Try order 1002 to test cross-user access.';
  fn=order?.owner_id==='bob'?'Identity is checked against the order’s owner before data is returned.':'Normal authorized behavior still works.';
 } else if(id==='sqli'){
  const products=[{id:1,name:'Studio headphones'},{id:2,name:'Mechanical keyboard'}];
  const attack=value==="' OR 1=1 -- ";
  const match=products.filter(p=>p.name.toLowerCase().includes(value.toLowerCase()));
  v=attack?[...products,{id:3,name:'Unreleased prototype'}]:match;f=match;
  vs=fs='200 OK';vn=attack?'The query’s public-product filter is bypassed.':'Only the supplied canonical injection payload is modeled here.';
  fn=attack?'The payload is treated as a search value, so no product matches.':'A normal product search remains available.';
 } else if(id==='xss'){
  v='<h1>Search results</h1><p>'+value+'</p>';
  const htmlEsc=value.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;'}[c]));
  f='<h1>Search results</h1><p>'+htmlEsc+'</p>';vs=fs='200 OK';
  vn='The local vulnerable page inserts this raw HTML. This hosted view displays it safely as text.';
  fn='HTML metacharacters are encoded. The browser sees the input as text.';
 } else if(id==='auth'){
  v={user:value||'alice'};f={error:'Valid session required'};vs='200 OK';fs='401 UNAUTHORIZED';
  vn='The header is accepted as an identity without proof.';fn='A client-supplied header cannot replace a valid signed session.';
 } else if(id==='race'){
  v={request_1:200,request_2:200,total_discount:20};f={request_1:200,request_2:409,total_discount:10};vs='2 ACCEPTED';fs='1 ACCEPTED';
  vn='Both requests observe an unused coupon before either consumes it.';fn='The atomic section allows exactly one request to consume the coupon.';
 } else {
  const a=state.reports?.vulnerable?.scans?.sca,b=state.reports?.fixed?.scans?.sca;
  const format=(r,pin)=>r?.status==='completed'?{dependency:pin,advisories:r.finding_count,ids:r.findings.map(f=>f.id)}:{dependency:pin,status:r?.status||'not_run',reason:r?.reason||'Audit report unavailable'};
  v=format(a,'requests==2.19.1');f=format(b,'requests==2.34.2');
  vs=a?.status==='completed'?a.finding_count+' ADVISORIES':'UNAVAILABLE';fs=b?.status==='completed'?b.finding_count+' ADVISORIES':'UNAVAILABLE';
  vn='Recorded direct-dependency audit; the old pin was never installed in the app.';
  fn='This is the result at the recorded scan time. Re-audit before using the version.';
 }
 return {v,f,vs,fs,vn,fn};
}
function runComparison(value){
 const s=selected(), r=simulate(s.id,String(value));
 for(const [prefix,data,status,note] of [['v',r.v,r.vs,r.vn],['f',r.f,r.fs,r.fn]]){
  const result=$('#'+prefix+'-result');result.textContent=pretty(data);result.classList.remove('placeholder');
  const tag=$('#'+prefix+'-status');tag.textContent=status;tag.className='status '+(prefix==='v'?'exposed':'protected');
  $('#'+prefix+'-note').textContent=note;
 }
 state.completed.add(s.id);
 const progress=$('.progress-label');if(progress)progress.innerHTML=`${state.completed.size} / 6 explored<div class="progress-track"><i style="width:${state.completed.size/6*100}%"></i></div>`;
 return {scenario:s.id,input:value,vulnerable:r.v,fixed:r.f};
}
const REPO = 'https://github.com/wwhosjess/SecureFlow-AppSec';
const HISTORICAL_EVIDENCE_COMMIT = 'db98c7991ce612914279091476689ec830105655';
const evidencePath = path => path
 .replace('reports/hardening-2026-10-04/ci/', 'evidence/2026-10-04/pipeline/')
 .replace('reports/hardening-2026-10-04/zap-final/', 'evidence/2026-10-04/zap-fixed/')
 .replace('reports/zap-2026-10-03/vulnerable/', 'evidence/2026-10-03/zap-vulnerable/')
 .replace('reports/hardening-2026-10-04/comparison.md', 'evidence/README.md');
const sourceLink = (path, label, sha) => sha
 ? `<span title="Original source commit: ${esc(sha)}">${esc(label)} (historical source unavailable)</span>`
 : `<a href="${REPO}/blob/main/${esc(evidencePath(path))}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`;
const historicalRunLink = (url, label) => `<span title="Original reference: ${esc(url)}">${esc(label)} (historical reference; unavailable publicly)</span>`;
const scanLabel = key => key==='dast'?'Targeted HTTP':key.toUpperCase();
function zapTriage(alert){
 const id=String(alert.pluginid);
 if(id==='43')return 'Likely false positive: response-similarity heuristic on reflected text. No source bytes or file read were demonstrated. Raw High severity is preserved; inspect exact fixed-run traffic and code below.';
 if(id==='10049')return 'Expected informational result: Cache-Control: no-store is intentional. Retained, not suppressed.';
 if(['40012','40026'].includes(id))return 'Expected vulnerable example: raw HTML reflection permits XSS. Fixed mode encodes text and applies CSP. Browser callback failures limit assurance from absent alerts.';
 return 'Hardening finding in the historical vulnerable mode. The final fixed report no longer contains this alert type after header hardening. Intentional vulnerable behavior is preserved.';
}
function renderPipeline(){
 main.innerHTML=renderHeader('Evidence, not just a green tick.','Recorded execution evidence from the Python lab and GitHub Actions. This browser view does not run scanners.')+`<div class="split-header"><div class="mode-tabs" aria-label="Report version"><button data-mode="vulnerable" class="${state.mode==='vulnerable'?'active':''}">Vulnerable run</button><button data-mode="fixed" class="${state.mode==='fixed'?'active':''}">Fixed run</button></div><a class="secondary" href="reports.json" download="secureflow-recorded-evidence.json">Download evidence JSON</a> <a href="reports.json" target="_blank" rel="noopener noreferrer">Open JSON</a></div><div id="evidence-content"></div>`;
 document.querySelectorAll('[data-mode]').forEach(b=>b.onclick=()=>{state.mode=b.dataset.mode;renderPipeline();});

 const content=$('#evidence-content');
 if(!state.reports){content.innerHTML=`<p class="notice">${state.reportError?'Evidence unavailable. Serve dist over HTTP and reload; unavailable evidence is not a pass.':'Loading recorded evidence…'}</p>`;return;}
 const bundle=state.reports,r=bundle[state.mode],run=bundle.pipeline_run,z=bundle.standalone_zap[state.mode];
 const alerts=z.raw.site.flatMap(site=>site.alerts||[]);
 const counts=[3,2,1,0].map(level=>alerts.filter(a=>Number(a.riskcode)===level).length);
 const completed=Object.values(r.scans).filter(s=>s.status==='completed').length;
 content.innerHTML=`<div class="notice"><strong>Browser simulation ≠ executable Python lab.</strong> The Security lab tab models fake responses safely. These scan results came from actual Python executions, not this page. Use the scan dates and source references below to identify the recorded executions.</div>
 <div class="evidence-summary"><div class="metric"><span class="eyebrow">SCOPED PIPELINE GATE</span><div class="metric-value">${esc(r.gate.toUpperCase())}</div><p>${r.gate==='pass'?'Zero findings in these checks; fixed mode is not fully secure.':'Intentional vulnerable examples detected.'}</p></div><div class="metric"><span class="eyebrow">COMPLETED CHECKS</span><div class="metric-value">${completed} / 3</div><p>SAST, SCA and targeted HTTP. ZAP runs separately.</p></div><div class="metric"><span class="eyebrow">RECORDED REGRESSIONS</span><div class="metric-value">${r.regression.status==='pass'?bundle.test_count+' passed':esc(r.regression.status)}</div><p>Includes attacks and legitimate behavior.</p></div></div>
 <p class="evidence-date">Pipeline scan: ${esc(r.generated_at)} (UTC). ${historicalRunLink(run.html_url,'Original Actions run')} · source ${sourceLink('lab/app.py',run.head_sha.slice(0,12),run.head_sha)} · ${sourceLink(bundle.evidence_path+'/ci/'+state.mode+'/summary.json','Raw summary')} · ${sourceLink(bundle.evidence_path+'/ci/'+state.mode+'/tests.txt','17-test execution log')}. Artifact links open preserved copies in the current public repository. Original run URLs and source IDs refer to the earlier development repository; they are retained for provenance and are unavailable publicly. Original evidence snapshot: ${esc(HISTORICAL_EVIDENCE_COMMIT)} (historical reference; unavailable publicly).</p>
 <section class="panel">${Object.entries(r.scans).map(([key,s])=>`<div class="scan-row"><span class="scan-category">${scanLabel(key)}</span><div><strong>${esc(s.tool)}</strong><p>${esc(s.scope||'Five known-attack HTTP checks; no JavaScript execution. Coupon timing varies.')}</p></div><span class="status">${esc(s.status)} · ${s.finding_count} ${key==='dast'?'exposed checks':key==='sca'?'unique advisories':'findings'}</span></div>`).join('')}</section>
 <section class="panel"><div class="panel-heading"><h2>Inspect pipeline evidence</h2></div>${Object.entries(r.scans).map(([key,s])=>`<details class="finding"><summary>${scanLabel(key)} · ${s.finding_count} findings</summary><pre>${esc(JSON.stringify(s,null,2))}</pre></details>`).join('')}</section>
 <section class="panel"><div class="panel-heading"><h2>ZAP · separate workflow</h2><span class="status">Exit ${z.run.zap_exit??z.run.zap_exit_code} · warnings</span></div><div class="panel-body"><p><strong>${counts[0]} High / ${counts[1]} Medium / ${counts[2]} Low / ${counts[3]} Informational</strong> raw alert types. Workflow success means usable evidence, not zero alerts.</p><p>Scan: ${esc(z.raw.created||z.raw['@generated'])} · ZAP ${esc(z.raw['@version'])} · ${historicalRunLink(z.run.html_url,'Original ZAP run')} · source ${sourceLink('lab/app.py',z.run.head_sha.slice(0,12),z.run.head_sha)}.</p><p>${sourceLink(z.path+'/zap.json','Original JSON')} · ${sourceLink(z.path+'/zap.html','Original HTML')} · ${sourceLink(bundle.evidence_path+'/comparison.md','Full triage and reliability review')}</p><p>Pipeline summary retains its original ZAP “not_run”: that pipeline does not invoke ZAP. The separate completed scan above is the actual ZAP evidence.</p><table class="order-table"><thead><tr><th>Recorded ZAP scan</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr></thead><tbody>${Object.entries(bundle.standalone_zap).map(([mode,record])=>{const rawAlerts=record.raw.site.flatMap(site=>site.alerts||[]);return `<tr><td>${esc(mode)} · ${esc((record.raw.created||record.run.created_at).slice(0,10))}</td>${[3,2,1,0].map(level=>`<td>${rawAlerts.filter(a=>Number(a.riskcode)===level).length}</td>`).join('')}</tr>`;}).join('')}</tbody></table><p>Different dates and source revisions; the vulnerable ZAP scan was not rerun after hardening. Counts are alert types, not distinct root causes.</p></div>
 ${alerts.map(a=>`<div class="finding"><strong>${esc(a.riskdesc)} · ${esc(a.alert||a.name)} · rule ${esc(a.pluginid)}</strong><p><b>Triage:</b> ${esc(zapTriage(a))}</p><details><summary>Unchanged raw alert and all instances</summary><pre>${esc(JSON.stringify(a,null,2))}</pre></details></div>`).join('')}</section>
 <section class="panel"><div class="panel-heading"><h2>Why source disclosure is a likely false positive</h2></div><div class="panel-body"><p>The fixed scanner sent <code>GET /reflect?q=reflect</code>. HTTP 200 returned <code>&lt;h1&gt;Search results&lt;/h1&gt;&lt;p&gt;reflect&lt;/p&gt;</code>. A random string returned the same template with that string. The route calls a constant template plus <code>html.escape(term)</code>, with no file access. This supports a likely false positive, not proven source disclosure; the raw High stays visible.</p><p>${sourceLink(bundle.evidence_path+'/zap-final/source-disclosure-exchanges.json','Exact traffic')} · ${sourceLink('lab/app.py#L87','Scanned code',run.head_sha)}</p><details><summary>Exact fixed scanner requests and responses</summary><pre>${esc(JSON.stringify(bundle.source_disclosure.exact_scanner_messages,null,2))}</pre></details><details><summary>Numbered code evidence</summary><pre>${esc(JSON.stringify(bundle.code_evidence,null,2))}</pre></details></div></section>
 <div class="notice"><strong>Coverage limits.</strong> SAST is one SQL syntax rule, not whole-project taint analysis. SCA audits direct fixture dependencies only; 5 vulnerable advisories came from 10 raw records, and do not prove app exploitability. Targeted HTTP uses known attacks. Unauthenticated ZAP missed the known vulnerable SQL injection and cannot establish Alice/Bob ownership or coupon-concurrency coverage. Final ZAP logs show 54 unsupported-method HTTP 501 responses, no captured HTTP 500/app traceback, and 13 network failures (12 internal callback DNS failures, one HTTPS-to-HTTP probe). Four browser setup warnings remain unresolved and limit browser-dependent coverage.</div><p class="source-detail">Recorded lab source SHA-256: ${esc(r.source_sha256)}</p>`;
}
function renderShop(){
 const rows=[{id:1001,owner:'alice',item:'Studio headphones',total:89},{id:1002,owner:'bob',item:'Mechanical keyboard',total:129}].filter(o=>o.owner===state.account);
 main.innerHTML=renderHeader('A tiny shop. A useful attack surface.','Synthetic products and accounts for the security exercises. No checkout, payments, or real customer data.')+`<div class="products"><div class="product"><div class="product-id">PRODUCT / 001</div><h2>Studio headphones</h2><div class="product-price">$89</div><p>Public catalog item.</p></div><div class="product"><div class="product-id">PRODUCT / 002</div><h2>Mechanical keyboard</h2><div class="product-price">$129</div><p>Public catalog item.</p></div><div class="product"><div class="product-id">PRODUCT / 003 · INTERNAL</div><h2>Unreleased prototype</h2><div class="product-price">Hidden</div><p>Fake internal record used in the SQL injection exercise.</p></div></div><section class="panel"><div class="panel-heading"><h2>My orders</h2><label class="select-account">Demo identity <select id="account"><option value="alice" ${state.account==='alice'?'selected':''}>Alice</option><option value="bob" ${state.account==='bob'?'selected':''}>Bob</option></select></label></div><div style="overflow:auto"><table class="order-table"><thead><tr><th>Order</th><th>Item</th><th>Total</th><th>Owner</th></tr></thead><tbody>${rows.map(o=>`<tr><td>#${o.id}</td><td>${o.item}</td><td>$${o.total}</td><td>${esc(o.owner)}</td></tr>`).join('')}</tbody></table></div><div class="panel-body"><button class="primary" id="open-idor">Test order authorization</button></div></section><div class="notice">The account selector changes a teaching identity in your browser. It is not a login system. The Python lab includes real login and session verification.</div>`;
 $('#account').onchange=e=>{state.account=e.target.value;renderShop();};$('#open-idor').onclick=()=>{state.scenario='idor';location.hash='lab';};
}
function renderGuide(){
 main.innerHTML=renderHeader('Take the lab beyond the browser.','Run the Python application, inspect HTTP traffic with Burp, and reproduce the scan evidence on your own machine.')+`<div class="guide-grid"><section class="panel"><div class="panel-heading"><h2>Run the executable lab</h2><a class="secondary" href="https://github.com/wwhosjess/SecureFlow-AppSec" target="_blank" rel="noopener noreferrer">Open source repository</a></div><div class="panel-body"><div class="step"><span class="step-num">01</span><div><h3>Clone or download the repository</h3><p>Use Python 3.12 or later. Open a terminal inside the SecureFlow project folder. The app itself has no third-party dependencies.</p></div></div><div class="step"><span class="step-num">02</span><div><h3>Run the deliberately vulnerable version</h3><p>The server binds only to your machine. Both demo users have password <code>demo-password</code>.</p><pre class="command">python -m lab.app --mode vulnerable --port 5050</pre></div></div><div class="step"><span class="step-num">03</span><div><h3>Try the cross-user request</h3><p>Open the URL below or send the request through Burp. The vulnerable mode defaults to Alice.</p><pre class="command">http://127.0.0.1:5050/orders/1002</pre></div></div><div class="step"><span class="step-num">04</span><div><h3>Run the fixed version</h3><p>In another terminal, start fixed mode on port 5051. Log in as Alice with POST /login, then request Bob’s order with the returned cookie: expect 403. Alice’s own order remains 200. <a class="guide-link" href="https://github.com/wwhosjess/SecureFlow-AppSec/blob/main/docs/reproduction.md" target="_blank" rel="noopener noreferrer">Exact commands and code explanation</a></p><pre class="command">python -m lab.app --mode fixed --port 5051</pre></div></div><div class="step"><span class="step-num">05</span><div><h3>Run the regression tests</h3><pre class="command">python -m unittest discover -s tests -v</pre></div></div><div class="step"><span class="step-num">06</span><div><h3>Install tools and generate a real report</h3><p>Use a virtual environment. A vulnerable scan exits with findings by design. Missing scanners block the gate.</p><pre class="command"># Follow the virtual-environment setup in README first.\npython -m pip install -r requirements-tools.txt\npython security_scan.py --mode vulnerable\npython security_scan.py --mode fixed</pre></div></div></div></section><div><section class="panel"><div class="panel-heading"><h2>Read alongside the code</h2></div><div class="panel-body"><p><a class="guide-link" href="https://portswigger.net/web-security/access-control" target="_blank" rel="noopener noreferrer">PortSwigger: access control</a></p><p><a class="guide-link" href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank" rel="noopener noreferrer">OWASP: SQL injection prevention</a></p><p><a class="guide-link" href="https://semgrep.dev/docs/writing-rules/testing-rules" target="_blank" rel="noopener noreferrer">Semgrep: testing custom rules</a></p><p><a class="guide-link" href="https://www.zaproxy.org/docs/docker/full-scan/" target="_blank" rel="noopener noreferrer">ZAP: full scan workflow</a></p></div></section></div></div>`;
}
function navigate(){let route=location.hash.slice(1);state.view=['lab','shop','pipeline','guide'].includes(route)?route:'lab';render();}
window.addEventListener('hashchange',navigate);navigate();
fetch('reports.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw new Error('Report unavailable');return r.json();}).then(data=>{state.reports=data;if(state.view==='pipeline')renderPipeline();}).catch(e=>{state.reportError=e.message;if(state.view==='pipeline')renderPipeline();});
if(document.modelContext?.registerTool){
 const lifetime=new AbortController();
 try{Promise.resolve(document.modelContext.registerTool({name:'run_security_exercise',title:'Run a security exercise',description:'Select a constrained fake-data exercise, run the input in both browser models, and display the comparison. No server scan is run.',inputSchema:{type:'object',properties:{scenario:{type:'string',enum:scenarios.map(s=>s.id)},input:{type:'string',maxLength:300}},required:['scenario','input'],additionalProperties:false},annotations:{readOnlyHint:false,untrustedContentHint:true},execute(input){if(!input||!scenarios.some(s=>s.id===input.scenario)||typeof input.input!=='string'||input.input.length>300||Object.keys(input).some(k=>!['scenario','input'].includes(k)))throw new Error('Invalid exercise input');state.scenario=input.scenario;state.view='lab';if(location.hash!=='#lab')history.replaceState(null,'','#lab');render();$('#payload').value=input.input;return runComparison(input.input);}},{signal:lifetime.signal})).catch(()=>{});}catch{}
 window.addEventListener('pagehide',()=>lifetime.abort(),{once:true});
}
