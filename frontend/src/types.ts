export type Lang='en'|'ar'|'fa';
export type Role='admin'|'analyst'|'viewer';
export type Identity={mode:'demo'|'authenticated';role:Role;username?:string;authenticated:boolean;mfa_enabled?:boolean;mfa_required?:boolean;can_refresh_global_sources?:boolean;workspace?:{slug:string;name:string}};
export type Source={id:'github'|'cisa'|'mitre'|'attack'|'epss';name:string;url:string;status:'error'|'cached'|'not_connected';last_success:string|null;last_attempt:string|null;error:string|null;count:number;version:string|null;released_at:string|null};
export type Epss={score:string;percentile:string;score_date:string;collected_at:string;source:string;classification:string};
export type Advisory={id:string;cve:string|null;summary:string;severity:string;url:string;published_at:string|null;collected_at:string;kev_status:string;kev_version:string|null;kev_collected_at:string|null;epss?:Epss|null};
export type Kev={cve:string;vendor:string;product:string;title:string;date_added:string;description:string;action:string;due_date:string;ransomware:string};
export type Investigation={id:number;title:string;status:'open'|'closed';created_at:string};
export type InvestigationDetail=Investigation & {evidence:{id:number;snapshot:Advisory;added_at:string;integrity?:{status:'MATCH'|'MISMATCH'|'NOT_RECORDED';sha256:string|null;algorithm:string|null}}[];notes:{id:number;content:string;classification:string;created_at:string}[];assets:InvestigationAsset[];techniques:InvestigationTechnique[]};
export type GraphNode={id:string;type:'INVESTIGATION'|'SOURCE_SNAPSHOT'|'ASSET_SNAPSHOT'|'TECHNIQUE_SNAPSHOT';label:string;url?:string};
export type GraphEdge={id:string;from:string;to:string;type:'REFERENCES'|'SCOPES_ASSET'|'REFERENCES_TECHNIQUE';timestamp:string;confidence:string;classification:'SOURCE-REPORTED'|'USER-ATTESTED'};
export type GraphData={nodes:GraphNode[];edges:GraphEdge[];limitations:string[]};
export type PageData<T>={items:T[];total:number;limit:number;offset:number};
export type SbomSummary={id:number;name:string;format:string;created_at:string;component_count:number};
export type SbomDetail=SbomSummary & {components:{id:number;name:string;version:string|null;purl:string|null;ecosystem:string|null;package_name:string|null}[];candidates:{id:number;component_id:number;advisory_id:string;snapshot:Advisory & {vulnerable_version_range?:string|null;vulnerable_version_ranges?:(string|null)[];version_assessment?:{status:'IN_RANGE'|'OUT_OF_RANGE'|'UNKNOWN';reason:string|null;algorithm:string;checked_version:string|null;supplied_version?:string|null}};version_evaluated:boolean}[];limitations:string[]};

export type CveRecord={epss?:Epss|null;cve:string;state:'PUBLISHED'|'REJECTED';description:string;description_language:string|null;assigner:string|null;date_published:string|null;date_updated:string|null;collected_at:string;source_sha:string;url:string};
export type Asset={id:number;name:string;asset_type:'domain'|'ip'|'application'|'cloud_resource'|'other';identifier:string;owner:string;scope_basis:string;status:'active'|'retired';created_by:string;created_at:string;updated_at:string;classification:'USER-ATTESTED';verification_status:'UNVERIFIED'};
export type InvestigationAsset={id:number;asset_id:number;snapshot:Asset;linked_by:string;linked_at:string};

export type AssetSbomLink={id:number;sbom_id:number;snapshot:SbomSummary & {candidate_count:number;classification:'USER-ATTESTED';verification_status:'UNVERIFIED'};linked_by:string;linked_at:string};
export type AttackTechnique={id:string;stix_id:string;name:string;description:string;tactics:string[];version:string|null;modified:string|null;revoked:boolean;deprecated:boolean;source_sha:string;collected_at:string;url:string;classification:'SOURCE-REPORTED';verification_status:'UNVERIFIED'};
export type InvestigationTechnique={id:number;technique_id:string;snapshot:AttackTechnique;linked_by:string;linked_at:string};
