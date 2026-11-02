import React,{useCallback,useEffect,useState} from 'react';
import {ShieldAlert} from 'lucide-react';
import {assetStrings} from './assetsI18n';
import type {Asset,InvestigationAsset,Lang,PageData,SbomSummary,AssetSbomLink} from './types';

type Api=<T>(path:string,options?:RequestInit)=>Promise<T>;
type AssetType=Asset['asset_type'];
const types:AssetType[]=['domain','ip','application','cloud_resource','other'];

type Props={lang:Lang;canWrite:boolean;api:Api};
export function Assets({lang,canWrite,api}:Props){
 const t=assetStrings[lang];
 const [page,setPage]=useState<PageData<Asset>|null>(null),[loading,setLoading]=useState(true),[busy,setBusy]=useState(false),[error,setError]=useState(false),[saved,setSaved]=useState(false),[query,setQuery]=useState(''),[name,setName]=useState(''),[type,setType]=useState<AssetType>('domain'),[identifier,setIdentifier]=useState(''),[owner,setOwner]=useState(''),[basis,setBasis]=useState(''),[authorized,setAuthorized]=useState(false),[confirm,setConfirm]=useState<Record<number,boolean>>({}),[expanded,setExpanded]=useState<number|null>(null),[editing,setEditing]=useState<number|null>(null);
 const load=useCallback(async(q='',offset=0)=>{setLoading(true);try{setPage(await api<PageData<Asset>>('/assets?'+new URLSearchParams({q,offset:String(offset),limit:'25'})));setError(false)}catch{setError(true)}finally{setLoading(false)}},[api]);
 useEffect(()=>{load()},[load]);
 async function create(e:React.FormEvent){
  e.preventDefault();if(!authorized||!canWrite)return;setBusy(true);setError(false);setSaved(false);
  try{await api(editing===null?'/assets':'/assets/'+editing+'/metadata',{method:editing===null?'POST':'PUT',body:JSON.stringify({name,asset_type:type,identifier,owner,scope_basis:basis,authorized})});setEditing(null);setName('');setIdentifier('');setOwner('');setBasis('');setAuthorized(false);setSaved(true);setQuery('');await load()}catch{setError(true)}finally{setBusy(false)}
 }
 async function status(asset:Asset){
  const activate=asset.status==='retired';if(!canWrite||(activate&&!confirm[asset.id]))return;setBusy(true);setError(false);
  try{await api('/assets/'+asset.id,{method:'PATCH',body:JSON.stringify({status:activate?'active':'retired',authorized:activate})});setConfirm({});await load(query,page?.offset||0)}catch{setError(true)}finally{setBusy(false)}
 }
 return <><div className="page-heading sub-heading"><div><div className="eyebrow"><span/>{t.name}</div><h1>{t.name}</h1><p>{t.description}</p></div></div><div className="notice"><ShieldAlert size={19}/><div><b>{t.unverified}</b><p>{t.warning}</p></div></div>
 {error&&<div role="alert" className="error-banner">{t.error}</div>}{saved&&<div role="status" className="asset-success">{t.saved}</div>}
 <div className="details-grid"><section className="panel detail-panel"><div className="panel-head"><div><h2>{editing===null?t.create:t.edit}</h2>{editing!==null&&<p>{t.editHint}</p>}</div></div><form className="detail-form" onSubmit={create}>
 <label htmlFor="asset-name">{t.assetName}</label><input id="asset-name" value={name} onChange={e=>setName(e.target.value)} maxLength={160} required/>
 <label htmlFor="asset-type">{t.type}</label><select id="asset-type" value={type} onChange={e=>setType(e.target.value as AssetType)}>{types.map(x=><option key={x} value={x}>{t[x]}</option>)}</select>
 <label htmlFor="asset-id">{t.identifier}</label><input id="asset-id" dir="ltr" value={identifier} onChange={e=>setIdentifier(e.target.value)} maxLength={512} required/>
 <label htmlFor="asset-owner">{t.owner}</label><input id="asset-owner" dir="auto" value={owner} onChange={e=>setOwner(e.target.value)} maxLength={160} required/>
 <label htmlFor="asset-basis">{t.basis}</label><textarea id="asset-basis" dir="auto" value={basis} onChange={e=>setBasis(e.target.value)} minLength={3} maxLength={2000} required/>
 <label className="asset-attestation"><input type="checkbox" checked={authorized} onChange={e=>setAuthorized(e.target.checked)} required/>{t.attest}</label><button className="primary" disabled={busy||!canWrite||!authorized}>{editing===null?t.create:t.saveEdit}</button>{editing!==null&&<button className="secondary" type="button" onClick={()=>{setEditing(null);setName('');setIdentifier('');setOwner('');setBasis('');setAuthorized(false)}}>{t.cancelEdit}</button>}</form></section>
 <section className="panel detail-panel"><div className="panel-head"><div><h2>{t.name}</h2></div></div><form className="search-row asset-search" onSubmit={e=>{e.preventDefault();load(query)}}><div className="inline-search"><input value={query} onChange={e=>setQuery(e.target.value)} placeholder={t.search} aria-label={t.search} maxLength={100}/></div><button className="secondary">{t.searchButton}</button></form>
 {loading?<div className="empty compact">{t.loading}</div>:!page?.items.length?<div className="empty compact">{t.empty}</div>:page.items.map(a=><article className="asset-item" key={a.id}><div className="component-head"><b dir="auto">{a.name}</b><span className={'state-pill '+(a.status==='active'?'good':'warn')}>{a.status==='active'?t.active:t.retired}</span></div><p><bdi>{t[a.asset_type]}</bdi> · <bdi dir="ltr">{a.identifier}</bdi> · <bdi>{a.owner}</bdi></p><p dir="auto">{t.scope}: {a.scope_basis}</p><small>{t.unverified}</small>{a.status==='retired'&&<label className="asset-attestation"><input type="checkbox" checked={!!confirm[a.id]} onChange={e=>setConfirm({...confirm,[a.id]:e.target.checked})}/>{t.retiredAttest}</label>}<button className="secondary small" disabled={busy||!canWrite||a.status!=='active'} onClick={()=>{setEditing(a.id);setName(a.name);setType(a.asset_type);setIdentifier(a.identifier);setOwner(a.owner);setBasis(a.scope_basis);setAuthorized(false);setSaved(false)}}>{t.edit}</button> <button className="secondary small" disabled={busy||!canWrite||(a.status==='retired'&&!confirm[a.id])} onClick={()=>status(a)}>{a.status==='active'?t.retire:t.reactivate}</button> <button className="secondary small" onClick={()=>setExpanded(expanded===a.id?null:a.id)} aria-expanded={expanded===a.id}>{expanded===a.id?t.closeSboms:t.sbomLinks}</button>{expanded===a.id&&<AssetSboms lang={lang} canWrite={canWrite} api={api} asset={a}/>}</article>)}
 {page&&<div className="pagination"><span>{t.showing} {page.total?page.offset+1:0}–{Math.min(page.offset+page.items.length,page.total)} / {page.total}</span><div><button className="secondary" disabled={loading||page.offset===0} onClick={()=>load(query,Math.max(0,page.offset-page.limit))}>{t.previous}</button><button className="secondary" disabled={loading||page.offset+page.limit>=page.total} onClick={()=>load(query,page.offset+page.limit)}>{t.next}</button></div></div>}</section></div></>;
}

export function InvestigationAssets({lang,canWrite,api,investigationId,links,onLinked}:Props&{investigationId:number;links:InvestigationAsset[];onLinked:()=>Promise<void>}){
 const t=assetStrings[lang];
 const [items,setItems]=useState<Asset[]>([]),[choice,setChoice]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState(false),[loading,setLoading]=useState(true);
 const load=useCallback(async()=>{setLoading(true);try{const page=await api<PageData<Asset>>('/assets?status=active&limit=100');setItems(page.items);setError(false)}catch{setError(true)}finally{setLoading(false)}},[api]);
 useEffect(()=>{load()},[load]);
 async function link(e:React.FormEvent){e.preventDefault();if(!choice||!canWrite)return;setBusy(true);setError(false);try{await api('/investigations/'+investigationId+'/assets',{method:'POST',body:JSON.stringify({asset_id:Number(choice)})});setChoice('');await onLinked()}catch{setError(true)}finally{setBusy(false)}}
 const choices=items.filter(a=>!links.some(link=>link.asset_id===a.id));
 return <section className="panel detail-panel asset-linked"><div className="panel-head"><div><h2>{t.selected}</h2><p>{t.snapshotNotice}</p></div></div>{error&&<div role="alert" className="error-banner">{t.error}</div>}
 <form className="detail-form" onSubmit={link}><label htmlFor="asset-select">{t.choose}</label><div className="form-row"><select id="asset-select" value={choice} onChange={e=>setChoice(e.target.value)} required><option value="">{loading?t.loading:choices.length?t.choose:t.unavailable}</option>{choices.map(a=><option key={a.id} value={a.id}>{a.name} · {a.identifier}</option>)}</select><button className="primary" disabled={busy||loading||!canWrite||!choice}>{t.link}</button></div><small>{t.maxSelection}</small></form>
 {links.length?links.map(link=><article className="asset-item" key={link.id}><div className="component-head"><b dir="auto">{link.snapshot.name}</b><span className="state-pill warn">{t.unverified}</span></div><p><bdi>{t[link.snapshot.asset_type]}</bdi> · <bdi dir="ltr">{link.snapshot.identifier}</bdi> · <bdi>{link.snapshot.owner}</bdi></p><p dir="auto">{t.scope}: {link.snapshot.scope_basis}</p><small>{t.statusAtLink}: {link.snapshot.status==='active'?t.active:t.retired} · {t.linkedBy}: <bdi>{link.linked_by}</bdi></small></article>):<div className="empty compact">{t.noneLinked}</div>}</section>;
}

function AssetSboms({lang,canWrite,api,asset}:Props&{asset:Asset}){
 const t=assetStrings[lang];
 const [sboms,setSboms]=useState<SbomSummary[]>([]),[links,setLinks]=useState<AssetSbomLink[]>([]),[choice,setChoice]=useState(''),[attested,setAttested]=useState(false),[busy,setBusy]=useState(false),[loading,setLoading]=useState(true),[error,setError]=useState(false);
 const load=useCallback(async()=>{setLoading(true);try{const [all,linked]=await Promise.all([api<SbomSummary[]>('/sboms'),api<{items:AssetSbomLink[]}>('/assets/'+asset.id+'/sboms')]);setSboms(all);setLinks(linked.items);setError(false)}catch{setError(true)}finally{setLoading(false)}},[api,asset.id]);
 useEffect(()=>{load()},[load]);
 async function link(e:React.FormEvent){e.preventDefault();if(!canWrite||!choice||!attested||asset.status!=='active')return;setBusy(true);setError(false);try{await api('/assets/'+asset.id+'/sboms',{method:'POST',body:JSON.stringify({sbom_id:Number(choice),attested})});setChoice('');setAttested(false);await load()}catch{setError(true)}finally{setBusy(false)}}
 const available=sboms.filter(x=>!links.some(link=>link.sbom_id===x.id));
 return <div className="asset-sboms"><p>{t.sbomWarning}</p>{error&&<div role="alert">{t.error}</div>}{loading?<small>{t.loading}</small>:<><form className="detail-form" onSubmit={link}><label htmlFor={'sbom-select-'+asset.id}>{t.chooseSbom}</label><select id={'sbom-select-'+asset.id} value={choice} onChange={e=>setChoice(e.target.value)} required><option value="">{t.chooseSbom}</option>{available.map(s=><option key={s.id} value={s.id}>{s.name} · {s.format}</option>)}</select><label className="asset-attestation"><input type="checkbox" checked={attested} onChange={e=>setAttested(e.target.checked)} required/>{t.sbomAttest}</label><button className="primary" disabled={busy||!canWrite||asset.status!=='active'||!choice||!attested}>{t.linkSbom}</button><small>{t.sbomSelection}</small></form>{links.length?links.map(l=><div className="asset-sbom-row" key={l.id}><b dir="auto">{l.snapshot.name}</b><small>{l.snapshot.format} · {l.snapshot.candidate_count} {t.candidates} · {t.unverified}</small></div>):<small>{t.noSboms}</small>}</>}</div>;
}
