import React,{useCallback,useEffect,useState} from 'react';
import {timelineStrings} from './timelineI18n';
import type {Lang} from './types';
type Api=<T>(path:string,options?:RequestInit)=>Promise<T>;
type Event={id:number;event_type:string;actor:string;details:Record<string,string|number>;created_at:string};
type Response={items:Event[];next_before:number|null;limitations:string[]};

export function Timeline({lang,api,investigationId,refreshKey}:{lang:Lang;api:Api;investigationId:number;refreshKey:string}){
 const t=timelineStrings[lang];const [items,setItems]=useState<Event[]>([]),[next,setNext]=useState<number|null>(null),[loading,setLoading]=useState(true),[error,setError]=useState(false);
 const load=useCallback(async(before?:number)=>{setLoading(true);try{const q=new URLSearchParams({limit:'50'});if(before)q.set('before',String(before));const data=await api<Response>('/investigations/'+investigationId+'/timeline?'+q);setItems(old=>before?[...old,...data.items]:data.items);setNext(data.next_before);setError(false)}catch{setError(true)}finally{setLoading(false)}},[api,investigationId]);
 useEffect(()=>{load()},[load,refreshKey]);
 function title(x:Event){return ({CASE_CREATED:t.created,STATUS_CHANGED:t.status,EVIDENCE_LINKED:t.evidence,NOTE_ADDED:t.note,ASSET_LINKED:t.asset,TECHNIQUE_LINKED:t.technique} as Record<string,string>)[x.event_type]||x.event_type}
 function status(v:string|number|undefined){return v==='open'?t.open:v==='closed'?t.closed:String(v||'—')}
 return <section className="panel detail-panel asset-linked"><div className="panel-head"><div><h2>{t.title}</h2><p>{t.warning}</p></div><button className="secondary small" disabled={loading} onClick={()=>load()}>{t.refresh}</button></div>{error&&<div role="alert" className="error-banner">{t.error}</div>}{loading&&!items.length?<div className="empty compact">{t.loading}</div>:items.length?items.map(x=><article className="timeline-row" key={x.id}><span className="timeline-dot"/><div><b>{title(x)}</b><small>{t.actor}: <bdi>{x.actor}</bdi> · <time dateTime={x.created_at}>{new Intl.DateTimeFormat(lang,{dateStyle:'medium',timeStyle:'short'}).format(new Date(x.created_at))}</time></small>{x.event_type==='STATUS_CHANGED'?<small>{t.from}: {status(x.details.from)} · {t.to}: {status(x.details.to)}</small>:x.details.advisory_id||x.details.asset_id||x.details.technique_id?<small>{t.reference}: <bdi>{x.details.advisory_id||x.details.asset_id||x.details.technique_id}</bdi></small>:x.details.classification?<small>{t.classification}: <bdi>{x.details.classification}</bdi></small>:null}</div></article>):!error&&<div className="empty compact">{t.empty}</div>}{next&&<div className="timeline-more"><button className="secondary" disabled={loading} onClick={()=>load(next)}>{loading?t.loading:t.more}</button></div>}</section>;
}
