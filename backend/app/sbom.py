"""Offline SBOM metadata parsing. Never fetches, opens or executes supplied content."""
import re
from urllib.parse import unquote
ECOSYSTEMS={'npm':'npm','pypi':'pip','pip':'pip','maven':'maven','nuget':'nuget','rubygems':'rubygems','gem':'rubygems','go':'go','golang':'go','cargo':'rust','rust':'rust','composer':'composer','packagist':'composer','swift':'swift'}

def normalize(eco,name):
    name=name.strip()
    if eco=='pip': return re.sub(r'[-_.]+','-',name.lower())
    if eco in ('npm','nuget'): return name.lower()
    return name

def parse_purl(value):
    if not isinstance(value,str) or not value.startswith('pkg:') or len(value)>2048:return None
    path=value[4:].split('?',1)[0].split('#',1)[0]
    if '/' not in path:return None
    typ,path=path.split('/',1); eco=ECOSYSTEMS.get(typ.lower())
    if not eco:return None
    if path.rfind('@')>path.rfind('/'):path,version=path.rsplit('@',1)
    else:version=None
    name=unquote(path).strip('/')
    if not name or len(name)>512 or len(version or '')>512:return None
    if eco=='maven' and '/' in name:
        namespace,artifact=name.rsplit('/',1);name=namespace+':'+artifact
    return {'ecosystem':eco,'package_name':name,'version':unquote(version) if version else None}

def extract(doc):
    if not isinstance(doc,dict):raise ValueError('SBOM must be an object')
    if doc.get('bomFormat')=='CycloneDX': fmt='CycloneDX'; records=doc.get('components',[])
    elif isinstance(doc.get('spdxVersion'),str) and doc['spdxVersion'].startswith('SPDX-'):fmt='SPDX';records=doc.get('packages',[])
    else:raise ValueError('Only CycloneDX or SPDX JSON is supported')
    if not isinstance(records,list) or len(records)>500:raise ValueError('Maximum 500 top-level components')
    items=[]
    for x in records:
        if not isinstance(x,dict):raise ValueError('Component must be an object')
        if fmt=='CycloneDX':purl=x.get('purl');name=x.get('name');version=x.get('version')
        else:
            refs=x.get('externalRefs',[])
            if not isinstance(refs,list):raise ValueError('SPDX externalRefs must be an array')
            purl=next((r.get('referenceLocator') for r in refs if isinstance(r,dict) and str(r.get('referenceType','')).lower() in ('purl','package-url')),None)
            name=x.get('name');version=x.get('versionInfo')
        parsed=parse_purl(purl)
        if not isinstance(name,str) or not name.strip():name=parsed['package_name'] if parsed else 'Unknown component'
        if not isinstance(version,str):version=parsed['version'] if parsed else None
        if len(name)>512 or len(version or '')>512 or (isinstance(purl,str) and len(purl)>2048):raise ValueError('Component field too long')
        items.append({'name':name,'version':version,'purl':purl if isinstance(purl,str) else None,'ecosystem':parsed['ecosystem'] if parsed else None,'package_name':parsed['package_name'] if parsed else None})
    return fmt,items
