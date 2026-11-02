# CICC — Cyber Intelligence Command Center

CICC is an **early, single-user development foundation**, not CICC v1.0 or an enterprise-ready security product. It contains a cohesive vertical slice: a multilingual command center, manually collected GitHub advisory metadata, local investigation tracking, source health, and an explicitly synthetic 2D graph. See [delivery status and architecture](docs/ARCHITECTURE.md) for the roadmap and limitations.

> **Security warning:** There is no authentication, authorization, tenant isolation, MFA, CSRF protection, encrypted storage, tamper-resistant audit, rate limiting, or safe evidence upload. Anyone who can reach the API can read and modify the workspace and trigger collection. Run only in a trusted, isolated development environment with non-sensitive data. The preview may be reachable by others with its URL. Do not expose this build to the internet or use it for real organizational intelligence.

## Run locally

Requirements: Node 20+, Python 3.11+, npm. From the repository root:

```sh
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
.venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```sh
cd frontend
npm ci
npm run dev
```

Open the Vite URL. It proxies `/api` to `127.0.0.1:8000`. For isolated preview environments, bind Vite and the API to the required interfaces; remember the security warning above. API documentation: `http://127.0.0.1:8000/docs`.

Click **Refresh source** to request the latest 30 GitHub public advisories. The request needs network access and is subject to GitHub's unauthenticated rate limits. Cached entries retain their source, publication and collection times and are identified as source-reported and unverified; the cache is not live. A failed refresh preserves earlier cached entries and displays the failure. The graph, globe, and critical-signal count are synthetic examples, not real observations.

## Tests

```sh
.venv/bin/python -m pytest -q backend/tests
cd frontend && npm run build
```

SQLite is stored in `backend/cicc.db` by default (override with `CICC_DB`). This file is ignored by Git. For development data only; back it up using SQLite's online backup mechanism after stopping writes. Recovery, encryption and restoration procedures have not been validated.

## What works

- English, Arabic, Persian interface and RTL direction switching without resetting the current page.
- GitHub public advisory retrieval, normalization and deduplication by GHSA identifier, cached local search, source health, error and freshness indicators.
- Create, list, close and reopen local investigations; record basic local activity.
- Interactive, keyboard-selectable synthetic 2D relationship graph with zoom/reset. The globe is an illustration, not a 3D or live map.
- Responsive command center, loading/error/empty states and API OpenAPI documentation.

**Not implemented:** enterprise authentication, permission enforcement, multi-workspace isolation, PostgreSQL/migrations, full provenance graph, additional intelligence feeds, evidence vault, authorized scanning, 3D/WebGL, AI agents, forecasting, autonomous workflows, federation, production operations or the other requested modules. UI localization is limited to this slice; third-party advisory content is not translated. See the roadmap before planning deployment.
