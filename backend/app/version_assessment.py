"""Conservative advisory range comparison, never a vulnerability verdict.

Only a deliberately small, documented subset of GitHub range syntax is evaluated.
Any unsupported or ambiguous value returns UNKNOWN rather than a negative result.
"""
import re
from packaging.specifiers import InvalidSpecifier, Specifier
from packaging.version import InvalidVersion, Version as PythonVersion
from semantic_version import Version as NpmVersion

ALGORITHM='cicc-range-subset-1'
RELEASE=re.compile(r'^\d+(?:\.\d+){0,3}$')
NPM_RELEASE=re.compile(r'^\d+\.\d+\.\d+$')
COMPARATOR=re.compile(r'^(<=|>=|<|>|=)\s*(\d+(?:\.\d+){0,3})$')


def compare(eco, version, purl_version, ranges):
    result={'status':'UNKNOWN','reason':None,'algorithm':ALGORITHM,'supplied_version':version,'checked_version':None}
    def unknown(reason):
        return {**result,'reason':reason}
    if eco not in ('pip','npm'): return unknown('unsupported_ecosystem')
    if not isinstance(version,str) or not version: return unknown('missing_version')
    if purl_version is not None and purl_version != version: return unknown('version_conflict')
    pattern=NPM_RELEASE if eco=='npm' else RELEASE
    if not pattern.fullmatch(version) or len(version)>80: return unknown('unsupported_version')
    try:
        current=(NpmVersion if eco=='npm' else PythonVersion)(version)
    except (ValueError,InvalidVersion): return unknown('unsupported_version')
    if not isinstance(ranges,list) or not ranges: return unknown('missing_ranges')
    inconclusive=False
    for expression in ranges:
        if not isinstance(expression,str) or not expression.strip() or len(expression)>1000:
            inconclusive=True; continue
        terms=expression.split(',')
        parsed=[]
        if len(terms)>20:
            inconclusive=True; continue
        for term in terms:
            match=COMPARATOR.fullmatch(term.strip())
            if not match or not pattern.fullmatch(match.group(2)):
                parsed=[]; break
            op,bound=match.groups()
            try:
                if eco=='pip': parsed.append(Specifier(('==' if op=='=' else op)+bound).contains(current))
                else:
                    target=NpmVersion(bound)
                    parsed.append({'<':current<target,'<=':current<=target,'>':current>target,'>=':current>=target,'=':current==target}[op])
            except (ValueError,InvalidVersion,InvalidSpecifier):
                parsed=[]; break
        if not parsed:
            inconclusive=True
        elif all(parsed):
            return {**result,'status':'IN_RANGE','reason':None,'checked_version':version}
    if inconclusive: return unknown('unsupported_range')
    return {**result,'status':'OUT_OF_RANGE','reason':None,'checked_version':version}
