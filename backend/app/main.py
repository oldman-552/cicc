"""CICC local development API. Not an authenticated multi-tenant service."""
import json
import os
import re
import sqlite3
import ssl
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

DB = os.getenv('CICC_DB', str(Path(__file__).resolve().parent.parent / 'cicc.db'))
app = FastAPI(title='CICC Development API', version='0.1.0', description='Local single-user prototype. Not for production deployment.')

def now():
    return datetime.now(timezone.utc).isoformat()

@contextmanager
def connection():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    finally:
        db.close()

def init_db():
    with connection() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS advisories (id TEXT PRIMARY KEY, summary TEXT NOT NULL, severity TEXT NOT NULL, url TEXT NOT NULL, published_at TEXT, collected_at TEXT NOT NULL, cve TEXT, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS investigations (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS source_status (name TEXT PRIMARY KEY, last_success TEXT, last_attempt TEXT, error TEXT, count INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, detail TEXT NOT NULL, timestamp TEXT NOT NULL);
        ''')

@app.on_event('startup')
def startup():
    init_db()

class InvestigationCreate(BaseModel):
    title: str = Field(min_length=3, max_length=160)

class InvestigationUpdate(BaseModel):
    status: Literal['open', 'closed']

@app.get('/api/health')
def health():
    return {'status':'ok','mode':'local-development','authentication':'not configured'}

@app.get('/api/sources')
def sources():
    with connection() as db:
        row = db.execute("SELECT * FROM source_status WHERE name='github_advisories'").fetchone()
    return [{'id':'github_advisories','name':'GitHub Security Advisories','url':'https://github.com/advisories','status': ('error' if row and row['error'] else 'cached' if row and row['last_success'] else 'not_connected'), 'last_success':row['last_success'] if row else None,'last_attempt':row['last_attempt'] if row else None,'error':row['error'] if row else None,'count':row['count'] if row else 0}]

@app.post('/api/sources/github/refresh')
def refresh_github():
    attempted = now()
    try:
        response = httpx.get('https://api.github.com/advisories', params={'per_page':30,'sort':'published','direction':'desc'}, headers={'Accept':'application/vnd.github+json','User-Agent':'CICC-development'}, timeout=15, follow_redirects=False, verify=ssl.create_default_context())
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            raise ValueError('Unexpected source response')
        collected = now()
        rows = []
        for item in data:
            if not isinstance(item, dict) or not isinstance(item.get('ghsa_id'), str) or not re.fullmatch(r'GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}', item['ghsa_id']):
                continue
            identifiers = item.get('identifiers') or []
            cve = next((i.get('value') for i in identifiers if isinstance(i, dict) and i.get('type') == 'CVE'), None)
            rows.append((item['ghsa_id'], item.get('summary') or 'No summary provided', item.get('severity') or 'unknown', 'https://github.com/advisories/' + item['ghsa_id'], item.get('published_at'), collected, cve, json.dumps(item)))
        if not rows:
            raise ValueError('No valid advisories in source response')
        with connection() as db:
            db.executemany('INSERT OR REPLACE INTO advisories VALUES (?,?,?,?,?,?,?,?)', rows)
            db.execute("INSERT OR REPLACE INTO source_status VALUES ('github_advisories',?,?,NULL,?)", (collected, attempted, len(rows)))
            db.execute('INSERT INTO audit(action,detail,timestamp) VALUES (?,?,?)', ('source.refresh',f'GitHub advisories: {len(rows)} records',collected))
        return {'imported':len(rows),'collected_at':collected}
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        with connection() as db:
            previous = db.execute("SELECT last_success,count FROM source_status WHERE name='github_advisories'").fetchone()
            db.execute("INSERT OR REPLACE INTO source_status VALUES ('github_advisories',?,?,?,?)", (previous['last_success'] if previous else None,attempted,str(exc)[:300],previous['count'] if previous else 0))
            db.execute('INSERT INTO audit(action,detail,timestamp) VALUES (?,?,?)', ('source.refresh_failed',str(exc)[:300],attempted))
        raise HTTPException(status_code=502, detail='Source refresh failed; previously cached records remain available.') from exc

@app.get('/api/advisories')
def advisories(q: str = Query(default='', max_length=100), limit: int = Query(default=20, ge=1, le=100)):
    with connection() as db:
        rows = db.execute('SELECT id,summary,severity,url,published_at,collected_at,cve FROM advisories WHERE summary LIKE ? OR id LIKE ? OR cve LIKE ? ORDER BY published_at DESC LIMIT ?', (f'%{q}%',f'%{q}%',f'%{q}%',limit)).fetchall()
    return [{**dict(row),'classification':'SOURCE-REPORTED','data_state':'CACHED','source':'GitHub Security Advisories','verification_status':'UNVERIFIED'} for row in rows]

@app.get('/api/investigations')
def investigations():
    with connection() as db:
        return [dict(r) for r in db.execute('SELECT * FROM investigations ORDER BY id DESC').fetchall()]

@app.post('/api/investigations', status_code=201)
def create_investigation(body: InvestigationCreate):
    title = body.title.strip()
    if len(title) < 3:
        raise HTTPException(422, 'Title must contain at least 3 non-space characters')
    timestamp = now()
    with connection() as db:
        cur = db.execute('INSERT INTO investigations(title,created_at) VALUES (?,?)',(title,timestamp))
        db.execute('INSERT INTO audit(action,detail,timestamp) VALUES (?,?,?)',('investigation.created',str(cur.lastrowid),timestamp))
        return dict(db.execute('SELECT * FROM investigations WHERE id=?',(cur.lastrowid,)).fetchone())

@app.patch('/api/investigations/{investigation_id}')
def update_investigation(investigation_id: int, body: InvestigationUpdate):
    with connection() as db:
        cur = db.execute('UPDATE investigations SET status=? WHERE id=?',(body.status,investigation_id))
        if not cur.rowcount:
            raise HTTPException(404, 'Investigation not found')
        db.execute('INSERT INTO audit(action,detail,timestamp) VALUES (?,?,?)',('investigation.status',f'{investigation_id}: {body.status}',now()))
        return dict(db.execute('SELECT * FROM investigations WHERE id=?',(investigation_id,)).fetchone())

@app.get('/api/audit')
def audit():
    with connection() as db:
        return [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100').fetchall()]
