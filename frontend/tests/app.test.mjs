import React from 'react';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {JSDOM} from 'jsdom';
import {createServer} from 'vite';
const dom=new JSDOM('<!doctype html><html><body></body></html>',{url:'https://test.example/'});
globalThis.window=dom.window;globalThis.document=dom.window.document;globalThis.localStorage=dom.window.localStorage;globalThis.Event=dom.window.Event;
Object.defineProperty(globalThis,'navigator',{value:dom.window.navigator,configurable:true});
dom.window.HTMLCanvasElement.prototype.getContext=()=>null;
globalThis.IS_REACT_ACT_ENVIRONMENT=true;
const {render,fireEvent,waitFor,cleanup}=await import('@testing-library/react');
const vite=await createServer({server:{middlewareMode:true},appType:'custom',logLevel:'silent'});
const {App}=await vite.ssrLoadModule('/src/main.tsx');
const json=(status,data)=>({ok:status>=200&&status<300,status,json:async()=>data});
const emptyPage={items:[],total:0,limit:30,offset:0};

test('demo workspace navigation and language changes retain page state',async()=>{
 localStorage.clear();
 globalThis.fetch=async(url,options={})=>{
   if(url==='/api/auth/session')return json(200,{mode:'demo',role:'admin',authenticated:false});
   if(url==='/api/sources'||url==='/api/investigations'||url==='/api/audit')return json(200,[]);
   if(String(url).startsWith('/api/advisories'))return json(200,emptyPage);
   if(url==='/api/overview')return json(200,{advisories:0,kev_entries:0,open_investigations:0});
   return json(404,{});
 };
 const ui=render(React.createElement(App));
 try{
   await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Intelligence, in focus.'})));
   assert.ok(ui.getByText('This preview has no authentication. Never enter sensitive information.'));
   fireEvent.click(ui.getByRole('button',{name:'Investigations'}));
   assert.ok(ui.getByRole('heading',{name:'Investigations'}));
   fireEvent.change(ui.getByLabelText('Language'),{target:{value:'ar'}});
   await waitFor(()=>assert.equal(document.documentElement.dir,'rtl'));
   assert.ok(ui.getByRole('heading',{name:'التحقيقات'}));
   fireEvent.change(ui.getByLabelText('اللغة'),{target:{value:'fa'}});
   await waitFor(()=>assert.equal(document.documentElement.lang,'fa'));
   assert.ok(ui.getByRole('heading',{name:'بررسی‌ها'}));
 }finally{cleanup()}
});

test('login and viewer permission state',async()=>{
 localStorage.clear();const calls=[];
 globalThis.fetch=async(url,options={})=>{
   calls.push(String(url));
   if(url==='/api/auth/session')return json(401,{});
   if(url==='/api/auth/login')return json(200,{mode:'authenticated',role:'viewer',username:'reader',authenticated:true,workspace:{slug:'acme',name:'Acme development'}});
   if(url==='/api/sources'||url==='/api/investigations')return json(200,[]);
   if(String(url).startsWith('/api/advisories'))return json(200,emptyPage);
   if(url==='/api/overview')return json(200,{advisories:0,kev_entries:0,open_investigations:0});
   return json(404,{});
 };
 const ui=render(React.createElement(App));
 try{
   await waitFor(()=>assert.ok(ui.getByLabelText('Username')));
   fireEvent.change(ui.getByLabelText('Username'),{target:{value:'reader'}});
   fireEvent.change(ui.getByLabelText('Password'),{target:{value:'password-long-enough'}});
   fireEvent.click(ui.getByRole('button',{name:'Sign in'}));
   await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Intelligence, in focus.'})));
   assert.equal(ui.getByRole('button',{name:'New investigation'}).disabled,true);
   assert.ok(ui.getByText('Acme development'));
   assert.ok(ui.getByText(/public sources are shared/));
   assert.equal(calls.includes('/api/audit'),false);
 }finally{cleanup()}
});

test.after(async()=>{await vite.close();dom.window.close()});

test('SBOM import sends metadata and displays the version limitation',async()=>{
 localStorage.clear();let submitted;
 globalThis.fetch=async(url,options={})=>{
  if(url==='/api/auth/session')return json(200,{mode:'demo',role:'admin',authenticated:false});
  if(url==='/api/sources'||url==='/api/investigations'||url==='/api/audit')return json(200,[]);
  if(String(url).startsWith('/api/advisories'))return json(200,emptyPage);
  if(url==='/api/overview')return json(200,{advisories:0,kev_entries:0,open_investigations:0});
  if(url==='/api/sboms'&&options.method==='POST'){submitted=JSON.parse(options.body);return json(201,{id:1})}
  if(url==='/api/sboms')return json(200,[]);
  if(url==='/api/sboms/1')return json(200,{id:1,name:'Synthetic test',format:'CycloneDX',created_at:'2025-01-01T00:00:00Z',components:[{id:1,name:'example',purl:'pkg:pypi/example@1',ecosystem:'pip'}],candidates:[{id:1,component_id:1,advisory_id:'GHSA-example',snapshot:{url:'https://github.com/advisories/GHSA-example',summary:'Example range',collected_at:'2025-01-01T00:00:00Z',vulnerable_version_ranges:['< 2.0','>= 3.0'],version_assessment:{status:'IN_RANGE',checked_version:'1.0',algorithm:'cicc-range-subset-1'}}},{id:2,component_id:1,advisory_id:'GHSA-legacy',snapshot:{url:'https://github.com/advisories/GHSA-legacy',summary:'Legacy snapshot',collected_at:'2025-01-01T00:00:00Z',vulnerable_version_range:'< 2.0'}}],limitations:['Limited comparison']});
  return json(404,{});
 };
 const ui=render(React.createElement(App));
 try {
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Intelligence, in focus.'})));
  fireEvent.click(ui.getByRole('button',{name:'SBOM intelligence'}));
  await waitFor(()=>assert.ok(ui.getByText('LIMITED VERSION COMPARISON · VERIFY MANUALLY')));
  fireEvent.change(ui.getByLabelText('SBOM name'),{target:{value:'Synthetic test'}});
  const file=new dom.window.File(['{}'],'test.json',{type:'application/json'});
  file.text=async()=>JSON.stringify({bomFormat:'CycloneDX',components:[{name:'example',purl:'pkg:pypi/example@1'}]});
  fireEvent.change(ui.getByLabelText('SBOM JSON file'),{target:{files:[file]}});
  fireEvent.submit(ui.getByRole('button',{name:'Import SBOM'}).closest('form')); 
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Synthetic test'})));
  assert.equal(submitted.document.bomFormat,'CycloneDX');
  assert.ok(ui.getByText('LIMITED VERSION COMPARISON · VERIFY MANUALLY'));
  assert.ok(ui.getByText('Within reported range — not confirmed'));
  assert.ok(ui.getByText('Unknown — version not evaluated'));
  assert.ok(ui.getByText('< 2.0 OR >= 3.0')); 
 } finally {cleanup()}
});

test('CVE records navigation and Arabic source disclosure',async()=>{
 localStorage.clear();
 globalThis.fetch=async(url,options={})=>{
  if(url==='/api/auth/session')return json(200,{mode:'demo',role:'admin',authenticated:false});
  if(url==='/api/sources'||url==='/api/investigations'||url==='/api/audit')return json(200,[]);
  if(String(url).startsWith('/api/advisories'))return json(200,emptyPage);
  if(url==='/api/overview')return json(200,{advisories:0,kev_entries:0,open_investigations:0});
  if(String(url).startsWith('/api/cves?'))return json(200,{...emptyPage,total:1,items:[{cve:'CVE-2025-12345',state:'PUBLISHED',description:'Source description',description_language:'en',assigner:'Example',date_updated:'2025-01-01T00:00:00Z',collected_at:'2025-01-01T00:00:00Z',source_sha:'a'.repeat(40),url:'https://github.com/CVEProject/cvelistV5',epss:{score:'0.005000000',percentile:'0.400000000',score_date:'2025-01-01',collected_at:'2025-01-01T00:00:00Z',source:'FIRST EPSS',classification:'MODEL ESTIMATE'}}]});
  return json(404,{});
 };
 const ui=render(React.createElement(App));
 try{
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Intelligence, in focus.'})));
  fireEvent.click(ui.getByRole('button',{name:'CVE records'}));
  await waitFor(()=>assert.ok(ui.getByRole('link',{name:'CVE-2025-12345'})));
  assert.ok(ui.getByText('Source description'));
  assert.ok(ui.getByText('0.005000000'));
  assert.ok(ui.getByText(/missing scores are unknown/));
  assert.ok(ui.getByText(/not independently verified/));
  fireEvent.change(ui.getByLabelText('Language'),{target:{value:'ar'}});
  await waitFor(()=>assert.equal(document.documentElement.dir,'rtl'));
  assert.ok(ui.getByRole('heading',{name:'سجلات CVE'}));
  assert.ok(ui.getByText(/لغة المصدر/));
 } finally {cleanup()}
});

test('asset inventory requires explicit attestation and submits manual metadata',async()=>{
 localStorage.clear();let submitted;let items=[];let sbomLinks=[];let sbomSubmission;let editSubmission;
 globalThis.fetch=async(url,options={})=>{
  if(url==='/api/auth/session')return json(200,{mode:'demo',role:'admin',authenticated:false});
  if(url==='/api/sources'||url==='/api/investigations'||url==='/api/audit')return json(200,[]);
  if(String(url).startsWith('/api/advisories'))return json(200,emptyPage);
  if(url==='/api/overview')return json(200,{advisories:0,kev_entries:0,open_investigations:0});
  if(url==='/api/assets'&&options.method==='POST'){submitted=JSON.parse(options.body);items=[{id:1,...submitted,status:'active',classification:'USER-ATTESTED',verification_status:'UNVERIFIED'}];return json(201,items[0])}
  if(url==='/api/assets/1/metadata'&&options.method==='PUT'){editSubmission=JSON.parse(options.body);items=[{...items[0],...editSubmission}];return json(200,items[0])}
  if(url==='/api/sboms')return json(200,[{id:7,name:'Synthetic BOM',format:'CycloneDX',component_count:1,created_at:'2025-01-01T00:00:00Z'}]);
  if(url==='/api/assets/1/sboms'&&options.method==='POST'){sbomSubmission=JSON.parse(options.body);sbomLinks=[{id:2,sbom_id:7,snapshot:{id:7,name:'Synthetic BOM',format:'CycloneDX',candidate_count:0},linked_by:'demo'}];return json(201,sbomLinks[0])}
  if(url==='/api/assets/1/sboms')return json(200,{items:sbomLinks});
  if(String(url).startsWith('/api/assets?'))return json(200,{...emptyPage,items,total:items.length});
  return json(404,{});
 };
 const ui=render(React.createElement(App));
 try{
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Intelligence, in focus.'})));
  fireEvent.click(ui.getByRole('button',{name:'Authorized asset inventory'}));
  await waitFor(()=>assert.ok(ui.getByText('No assets recorded.')));
  assert.ok(ui.getByText(/not independently verified/));
  const submit=ui.getByRole('button',{name:'Register asset'});assert.equal(submit.disabled,true);
  fireEvent.change(ui.getByLabelText('Asset name'),{target:{value:'Synthetic asset'}});
  fireEvent.change(ui.getByLabelText('Asset identifier'),{target:{value:'example.test'}});
  fireEvent.change(ui.getByLabelText('Owner or responsible team'),{target:{value:'Test team'}});
  fireEvent.change(ui.getByLabelText('Authorization / scope basis'),{target:{value:'Test authorization'}});
  fireEvent.click(ui.getByLabelText('I attest that this asset is within my authorized scope.'));
  assert.equal(submit.disabled,false);fireEvent.click(submit);
  await waitFor(()=>assert.ok(ui.getByText('Synthetic asset')));
  assert.equal(submitted.authorized,true);assert.equal(submitted.identifier,'example.test');
  fireEvent.click(ui.getByRole('button',{name:'SBOM associations'}));
  await waitFor(()=>assert.ok(ui.getByRole('option',{name:'Synthetic BOM · CycloneDX'})));
  fireEvent.change(ui.getByLabelText('Choose an imported SBOM'),{target:{value:'7'}});
  assert.equal(ui.getByRole('button',{name:'Link SBOM'}).disabled,true);
  fireEvent.click(ui.getByLabelText('I attest this SBOM is associated with this asset.'));
  fireEvent.click(ui.getByRole('button',{name:'Link SBOM'}));
  await waitFor(()=>assert.ok(ui.getByText('Synthetic BOM')));
  assert.deepEqual(sbomSubmission,{sbom_id:7,attested:true});
  assert.ok(ui.getByText(/not proof of deployment/));
  fireEvent.click(ui.getByRole('button',{name:'Edit asset'}));
  const save=ui.getByRole('button',{name:'Save changes'});assert.equal(save.disabled,true);
  fireEvent.change(ui.getByLabelText('Asset name'),{target:{value:'Updated synthetic asset'}});
  fireEvent.click(ui.getByLabelText('I attest that this asset is within my authorized scope.'));
  fireEvent.click(save);
  await waitFor(()=>assert.ok(ui.getByText('Updated synthetic asset')));
  assert.equal(editSubmission.authorized,true);
  fireEvent.change(ui.getByLabelText('Language'),{target:{value:'ar'}});
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'سجل الأصول المصرّح بها',level:1})));
  assert.equal(document.documentElement.dir,'rtl');
 }finally{cleanup()}
});

test('investigation asset link is shown as unverified scope and appears in 2D graph',async()=>{
 localStorage.clear();let linked=false;let linkRequest;
 const asset={id:1,name:'Test application',asset_type:'application',identifier:'example.test',owner:'Test team',scope_basis:'Test authorization',status:'active',created_by:'demo',created_at:'2025-01-01T00:00:00Z',updated_at:'2025-01-01T00:00:00Z',classification:'USER-ATTESTED',verification_status:'UNVERIFIED'};
 const investigation={id:1,title:'Case example',status:'open',created_at:'2025-01-01T00:00:00Z'};
 globalThis.fetch=async(url,options={})=>{
  if(url==='/api/auth/session')return json(200,{mode:'demo',role:'admin',authenticated:false});
  if(url==='/api/sources'||url==='/api/audit')return json(200,[]);
  if(url==='/api/investigations')return json(200,[investigation]);
  if(url==='/api/investigations/1/assets'&&options.method==='POST'){linkRequest=JSON.parse(options.body);linked=true;return json(201,{id:1})}
  if(url==='/api/investigations/1')return json(200,{...investigation,evidence:[],notes:[],assets:linked?[{id:1,asset_id:1,snapshot:asset,linked_by:'demo',linked_at:'2025-01-01T00:00:00Z'}]:[]});
  if(String(url).startsWith('/api/investigations/1/timeline?'))return json(200,{items:[],next_before:null,limitations:[]});
  if(String(url).startsWith('/api/assets?'))return json(200,{...emptyPage,items:[asset],total:1});
  if(String(url).startsWith('/api/techniques?'))return json(200,emptyPage);
  if(String(url).startsWith('/api/advisories'))return json(200,emptyPage);
  if(url==='/api/overview')return json(200,{advisories:0,kev_entries:0,open_investigations:1});
  if(url==='/api/graph')return json(200,{nodes:[{id:'investigation:1',type:'INVESTIGATION',label:'Case example'},{id:'asset-link:1',type:'ASSET_SNAPSHOT',label:'Test application · example.test'}],edges:[{id:'asset-link:1',from:'investigation:1',to:'asset-link:1',type:'SCOPES_ASSET',timestamp:'2025-01-01T00:00:00Z',confidence:'NOT ASSESSED',classification:'USER-ATTESTED'}],limitations:[]});
  return json(404,{});
 };
 const ui=render(React.createElement(App));
 try{
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Intelligence, in focus.'})));
  await waitFor(()=>assert.ok(ui.getByText('Case example')));
  fireEvent.click(ui.getByRole('button',{name:'Investigations'}));
  fireEvent.click(ui.getByRole('button',{name:'View'}));
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Linked assets'})));
  await waitFor(()=>assert.ok(ui.getByRole('option',{name:'Test application · example.test'})));
  fireEvent.change(ui.getByLabelText('Choose an active asset'),{target:{value:'1'}});
  fireEvent.click(ui.getByRole('button',{name:'Link asset'}));
  await waitFor(()=>assert.ok(ui.getByText('Test application')));
  assert.equal(linkRequest.asset_id,1);
  assert.ok(ui.getByText(/A link does not establish exposure/));
  fireEvent.click(ui.getByRole('button',{name:'Intelligence graph'}));
  await waitFor(()=>assert.ok(ui.getByText('SCOPES ASSET')));
  assert.ok(ui.getByText('3D is unavailable on this device. Use the reference list below.'));
  assert.ok(ui.getByRole('button',{name:'Test application · example.test'}));
 }finally{cleanup()}
});

test('ATT&CK source and investigation links are labeled as reference, not evidence',async()=>{
 localStorage.clear();let linked=false;let request;
 const item={id:'T1234',stix_id:'attack-pattern--00000000-0000-4000-8000-000000000001',name:'Synthetic reference',description:'Reference description',tactics:['execution'],version:'1.0',modified:'2025-01-01',revoked:false,deprecated:false,source_sha:'a'.repeat(40),collected_at:'2025-01-01T00:00:00Z',url:'https://attack.mitre.org/techniques/T1234/',classification:'SOURCE-REPORTED',verification_status:'UNVERIFIED'};
 const investigation={id:1,title:'Reference case',status:'open',created_at:'2025-01-01T00:00:00Z'};
 globalThis.fetch=async(url,options={})=>{
  if(url==='/api/auth/session')return json(200,{mode:'demo',role:'admin',authenticated:false});
  if(url==='/api/sources'||url==='/api/audit')return json(200,[]);
  if(url==='/api/investigations')return json(200,[investigation]);
  if(url==='/api/investigations/1/techniques'&&options.method==='POST'){request=JSON.parse(options.body);linked=true;return json(201,{id:1})}
  if(url==='/api/investigations/1')return json(200,{...investigation,evidence:[],notes:[],assets:[],techniques:linked?[{id:1,technique_id:item.id,snapshot:item,linked_by:'demo',linked_at:'2025-01-01T00:00:00Z'}]:[]});
  if(String(url).startsWith('/api/investigations/1/timeline?'))return json(200,{items:[],next_before:null,limitations:[]});
  if(String(url).startsWith('/api/techniques?'))return json(200,{...emptyPage,items:[item],total:1});
  if(String(url).startsWith('/api/assets?'))return json(200,emptyPage);
  if(String(url).startsWith('/api/advisories'))return json(200,emptyPage);
  if(url==='/api/overview')return json(200,{advisories:0,kev_entries:0,open_investigations:1});
  return json(404,{});
 };
 const ui=render(React.createElement(App));
 try{
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Intelligence, in focus.'})));
  fireEvent.click(ui.getByRole('button',{name:'ATT&CK reference'}));
  await waitFor(()=>assert.ok(ui.getByRole('link',{name:/T1234/})));
  assert.ok(ui.getByText(/not the full catalog or trending activity/));
  fireEvent.change(ui.getByLabelText('Language'),{target:{value:'fa'}});
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'مرجع ATT&CK'})));
  assert.equal(document.documentElement.dir,'rtl');
  fireEvent.change(ui.getByLabelText('زبان'),{target:{value:'en'}});
  fireEvent.click(ui.getByRole('button',{name:'Investigations'}));
  await waitFor(()=>assert.ok(ui.getByRole('button',{name:'View'})));
  fireEvent.click(ui.getByRole('button',{name:'View'}));
  await waitFor(()=>assert.ok(ui.getByRole('option',{name:'T1234 · Synthetic reference'})));
  assert.ok(ui.getByText(/does not establish activity, attribution or compromise/));
  fireEvent.change(ui.getByLabelText('Choose a cached active technique'),{target:{value:'T1234'}});
  fireEvent.click(ui.getByRole('button',{name:'Link reference'}));
  await waitFor(()=>assert.ok(ui.getByRole('link',{name:'T1234 · Synthetic reference'})));
  assert.deepEqual(request,{technique_id:'T1234'});
 }finally{cleanup()}
});

test('investigation timeline paginates and warns that prior history is incomplete',async()=>{
 localStorage.clear();const caseItem={id:1,title:'Timeline case',status:'open',created_at:'2025-01-01T00:00:00Z'};
 globalThis.fetch=async(url)=>{
  if(url==='/api/auth/session')return json(200,{mode:'demo',role:'admin',authenticated:false});
  if(url==='/api/sources'||url==='/api/audit')return json(200,[]);
  if(url==='/api/investigations')return json(200,[caseItem]);
  if(url==='/api/investigations/1')return json(200,{...caseItem,evidence:[],notes:[],assets:[],techniques:[]});
  if(String(url).startsWith('/api/investigations/1/timeline?'))return json(200,String(url).includes('before=2')?{items:[{id:1,event_type:'CASE_CREATED',actor:'demo',details:{},created_at:'2025-01-01T00:00:00Z'}],next_before:null}:{items:[{id:2,event_type:'STATUS_CHANGED',actor:'demo',details:{from:'closed',to:'open'},created_at:'2025-01-01T01:00:00Z'}],next_before:2});
  if(String(url).startsWith('/api/assets?')||String(url).startsWith('/api/techniques?')||String(url).startsWith('/api/advisories'))return json(200,emptyPage);
  if(url==='/api/overview')return json(200,{advisories:0,kev_entries:0,open_investigations:1});
  return json(404,{});
 };
 const ui=render(React.createElement(App));
 try{
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Intelligence, in focus.'})));
  fireEvent.click(ui.getByRole('button',{name:'Investigations'}));
  await waitFor(()=>assert.ok(ui.getByRole('button',{name:'View'})));fireEvent.click(ui.getByRole('button',{name:'View'}));
  await waitFor(()=>assert.ok(ui.getByText('Status changed')));
  assert.ok(ui.getByText(/Events before this feature was enabled are not backfilled/));
  fireEvent.click(ui.getByRole('button',{name:'Load older events'}));
  await waitFor(()=>assert.ok(ui.getByText('Investigation created')));
  fireEvent.change(ui.getByLabelText('Language'),{target:{value:'ar'}});
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'الخط الزمني للتحقيق'})));
  assert.ok(ui.getByText('أُنشئ التحقيق'));
 }finally{cleanup()}
});

test('a mismatched snapshot checksum is surfaced without claiming tamper protection',async()=>{
 localStorage.clear();const caseItem={id:1,title:'Integrity case',status:'open',created_at:'2025-01-01T00:00:00Z'};
 const snapshot={id:'GHSA-test-test-test',cve:'CVE-2025-12345',summary:'Example advisory',severity:'high',url:'https://github.com/advisories/GHSA-test-test-test',published_at:'2025-01-01T00:00:00Z',collected_at:'2025-01-01T00:00:00Z',kev_status:'UNKNOWN'};
 globalThis.fetch=async(url)=>{
  if(url==='/api/auth/session')return json(200,{mode:'demo',role:'admin',authenticated:false});
  if(url==='/api/sources'||url==='/api/audit')return json(200,[]);
  if(url==='/api/investigations')return json(200,[caseItem]);
  if(url==='/api/investigations/1')return json(200,{...caseItem,notes:[],assets:[],techniques:[],evidence:[{id:1,snapshot,added_at:'2025-01-01T00:00:00Z',integrity:{status:'MISMATCH',sha256:'a'.repeat(64),algorithm:'cicc-json-sha256-v1'}}]});
  if(String(url).startsWith('/api/investigations/1/timeline?'))return json(200,{items:[],next_before:null});
  if(String(url).startsWith('/api/assets?')||String(url).startsWith('/api/techniques?')||String(url).startsWith('/api/advisories'))return json(200,emptyPage);
  if(url==='/api/overview')return json(200,{advisories:0,kev_entries:0,open_investigations:1});
  return json(404,{});
 };
 const ui=render(React.createElement(App));
 try{
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Intelligence, in focus.'})));
  fireEvent.click(ui.getByRole('button',{name:'Investigations'}));
  await waitFor(()=>assert.ok(ui.getByRole('button',{name:'View'})));fireEvent.click(ui.getByRole('button',{name:'View'}));
  await waitFor(()=>assert.ok(ui.getByText('Stored checksum does not match')));
  assert.ok(ui.getByText('Stored alongside the snapshot; not tamper-proof or proof of authenticity.'));
  assert.ok(ui.getByText('a'.repeat(64)));
  fireEvent.change(ui.getByLabelText('Language'),{target:{value:'ar'}});
  await waitFor(()=>assert.ok(ui.getByText('لا تطابق بصمة التحقق المخزنة')));
 }finally{cleanup()}
});

test('audit loads paginated workspace events and discloses limitations in Arabic',async()=>{
 localStorage.clear();const calls=[];
 globalThis.fetch=async(url)=>{
  url=String(url);calls.push(url);
  if(url==='/api/auth/session')return json(200,{mode:'demo',role:'admin',authenticated:false});
  if(url==='/api/sources'||url==='/api/investigations')return json(200,[]);
  if(url.startsWith('/api/advisories'))return json(200,emptyPage);
  if(url==='/api/overview')return json(200,{advisories:0,kev_entries:0,open_investigations:0});
  if(url.startsWith('/api/audit/events?')){
   const q=new URL(url,'https://test.example').searchParams;
   return json(200,q.has('before')?{items:[{id:1,actor:'tester',action:'note.created',detail:'1',created_at:'2025-01-01T00:00:00Z'}],next_before:null}:{items:[{id:2,actor:'tester',action:'source.refresh',detail:'github',created_at:'2025-01-02T00:00:00Z'}],next_before:2});
  }
  return json(404,{});
 };
 const ui=render(React.createElement(App));
 try{
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Intelligence, in focus.'})));
  assert.equal(calls.some(x=>x.startsWith('/api/audit/')),false);
  fireEvent.click(ui.getByRole('button',{name:'Audit trail'}));
  await waitFor(()=>assert.ok(ui.getByText('source.refresh')));
  assert.ok(ui.getByText(/not a tamper-evident audit trail/));
  fireEvent.click(ui.getByRole('button',{name:'Load older events'}));
  await waitFor(()=>assert.ok(ui.getByText('note.created')));
  assert.ok(calls.some(x=>x.includes('before=2')));
  fireEvent.change(ui.getByLabelText('Exact action (optional)'),{target:{value:'source.refresh'}});
  fireEvent.click(ui.getByRole('button',{name:'Apply filter'}));
  await waitFor(()=>assert.ok(calls.some(x=>x.includes('action=source.refresh'))));
  fireEvent.change(ui.getByLabelText('Language'),{target:{value:'ar'}});
  await waitFor(()=>assert.ok(ui.getByText(/السجلات المحلية قابلة للتعديل/)));
 } finally {cleanup()}
});

test('EPSS estimate and uncertainty are visible in English and Arabic',async()=>{
 localStorage.clear();
 const advisory={id:'GHSA-test-test-test',cve:'CVE-2025-1234',summary:'Synthetic advisory',severity:'high',url:'https://github.com/advisories/GHSA-test-test-test',published_at:'2025-01-01T00:00:00Z',collected_at:'2025-04-01T00:00:00Z',kev_status:'UNKNOWN',kev_version:null,kev_collected_at:null,epss:{score:'0.012340000',percentile:'0.710000000',score_date:'2025-04-01',collected_at:'2025-04-01T12:00:00Z',source:'FIRST EPSS',classification:'MODEL ESTIMATE'}};
 globalThis.fetch=async(url)=>{
  url=String(url);
  if(url==='/api/auth/session')return json(200,{mode:'demo',role:'admin',authenticated:false});
  if(url==='/api/sources')return json(200,[{id:'epss',name:'FIRST EPSS',url:'https://api.first.org/data/v1/epss',status:'cached',last_success:'2025-04-01T12:00:00Z',last_attempt:'2025-04-01T12:00:00Z',count:1,version:null,released_at:null}]);
  if(url==='/api/investigations')return json(200,[]);
  if(url.startsWith('/api/advisories'))return json(200,{...emptyPage,items:[advisory],total:1});
  if(url==='/api/overview')return json(200,{advisories:1,kev_entries:0,open_investigations:0});
  return json(404,{});
 };
 const ui=render(React.createElement(App));
 try{
  await waitFor(()=>assert.ok(ui.getByRole('heading',{name:'Intelligence, in focus.'})));
  fireEvent.click(ui.getByRole('button',{name:'Security advisories'}));
  await waitFor(()=>assert.ok(ui.getByText('0.012340000')));
  assert.ok(ui.getByText(/missing scores are unknown/));
  assert.ok(ui.getByText('0.710000000'));
  fireEvent.change(ui.getByLabelText('Language'),{target:{value:'ar'}});
  assert.ok(ui.getByText(/الدرجة المفقودة غير معروفة/));
  assert.ok(ui.getByText(/تقدير EPSS/));
 } finally {cleanup()}
});
