# Architecture, delivery status & roadmap

## Repository assessment

The starting repository contained only `README.md` and no application, dependencies, data model or tests. This delivery establishes an initial vertical slice rather than claiming completion of the requested enterprise system.

## Current architecture

```text
Browser (React/Vite, en/ar/fa, 2D SVG)
    | /api (Vite development proxy)
    v
FastAPI (single-user, unauthenticated)
    |                         |
    v                         v
SQLite local cache      GitHub public advisories API
advisories,             (manual request, fixed URL)
investigations,
source status, audit
```

SQLite tables are initialized on startup; this is not a migration system. `advisories.id` is the GHSA stable key. An advisory has source URL, publication/collection timestamps, severity, optional CVE, and raw response; responses expose source-reported/unverified/cached labels. Investigations contain title, status and creation time. The audit table records investigation and refresh actions, but is neither complete nor immutable. No organization, user, permission or evidence data model exists yet. The example graph is isolated static synthetic UI data, not stored intelligence.

## Existing API contracts

OpenAPI is generated at `/docs` and `/openapi.json` while the API runs.

- `GET /api/health`: development mode and authentication status.
- `GET /api/sources`: GitHub source status, counts, collection times and error.
- `POST /api/sources/github/refresh`: fetch up to 30 recent public advisories; `502` on failure, retaining the old cache.
- `GET /api/advisories?q=&limit=`: local cached advisory search (max 100 returned).
- `GET /api/investigations`, `POST /api/investigations` and `PATCH /api/investigations/{id}`: local investigation lifecycle.
- `GET /api/audit`: most recent 100 local audit entries.

Collection has a fixed endpoint, TLS validation, request timeout and response shape check, and never executes downloaded content. It has no retry, scheduler, configurable limits or explicit rate-limit backoff. The current cache accumulates updates by identifier; source count reflects the most recent batch, not the total cached count. The UI searches at most 100 recently published cached records; this is not unified search. No external source response is independently verified.

## Intended dependency map

1. **Foundation:** identity/MFA, tenant and workspace boundaries, permission model, secure sessions, PostgreSQL migrations, audit and retention, translations.
2. **Collection:** source registry and adapters, scheduling, retries, rate limits, normalized records, provenance, source health and deduplication; depends on foundation.
3. **Investigation and search:** evidence vault, scoped search, investigation workflow and alerts; depends on foundation and collection.
4. **Fusion and graph:** source-backed entities, typed evidence-backed relationships, confidence and lineage; depends on collection and investigation.
5. **Defense and research:** asset authorization and scope, exposure, cloud, malware metadata, SBOM, research library and supplier risk; depends on identity, collection and graph.
6. **Decision support and AI:** model registry, scoped retrieval, attribution, approval gates, human review, scenario simulation and agent governance; depends on evidence, permissions and fusion.
7. **Presentation and federation:** production 3D and accessible 2D, executive reporting, secure STIX/TAXII exchange; depends on graph, permissions and provenance.
8. **Operations:** metrics, security hardening, backup/restore tests, disaster recovery, load/security testing and deployment gates across all phases.

## Target model and security boundaries (design, not implemented)

- Organization → Workspace → User/Role/Permission. Every tenant-owned record and query must carry a workspace boundary and enforce authorization server-side.
- Source → Collection → Evidence → Entity/Relationship → Assessment → Decision. All relationships need evidence, timestamps, confidence, classification and verification status; claims must not become facts implicitly.
- Investigation → notes, evidence references, tasks, decisions and audit events. Evidence must be immutable/versioned and access-controlled.
- Asset → explicit ownership/authorization/scope before any assessment. No scanning exists in this build.
- AI assessment → model/prompt version, source references, uncertainty, assumptions and review state; inferred conclusions remain unverified. No AI exists in this build.
- External adapters should be fixed or allowlisted, validate input, enforce quotas and retry policy, preserve licensing and never execute collected files.

## Phase report / module matrix

| Area | Status | Evidence / limitation |
|---|---|---|
| Development foundation | IN DEVELOPMENT | React/FastAPI/SQLite; no identity, RBAC or migrations |
| Command center | IN DEVELOPMENT | Local dashboard, explicit synthetic graphic, no real threat map |
| GitHub advisories | TESTED | Manual live collection tested, cache and failure behavior tested; no scheduler/retry |
| Local investigation tracking | TESTED | Create/list/close/reopen and basic action log tested; no collaboration or evidence |
| Search | IN DEVELOPMENT | Local advisory and investigation filtering only |
| i18n | IN DEVELOPMENT | Three UI languages in this slice; external content not translated; no formal localization QA |
| 2D relationship demonstration | IN DEVELOPMENT | Static synthetic nodes with keyboard selection and zoom; no production graph or 3D |
| Source health | IN DEVELOPMENT | One fixed GitHub adapter with timestamps/errors |
| Security, tenants, MFA, governance | NOT STARTED | No deployment-safe access controls |
| NVD, CISA KEV, EPSS, OSV, news | NOT STARTED | No adapters or collected data |
| Evidence, authorized asset defense, research, cloud, SBOM | NOT STARTED | No backend workflows |
| Fusion, business impact, predictive analytics | NOT STARTED | No evidence-backed correlation or models |
| AI agents, AI governance, autonomous workflows | NOT STARTED | No AI provider or execution framework |
| 3D universe, federation, disaster recovery | NOT STARTED | No implementation or verified recovery |

### Phase 1 report

- Completed in this slice: basic application shell, development database and API, translations for visible core workflows, basic local activity logging.
- Connected data source: GitHub advisories; manually refreshed successfully in the development environment. No other source is connected.
- Database: four SQLite tables created on startup. No migration tooling.
- Security: fixed source URL, TLS validation, bounded query limits, input validation, no execution of collected materials; no authentication or tenant controls.
- Tests: backend API tests for lifecycle, validation, cache refresh, search and failure retention; frontend production build. These are not security, browser, accessibility, load or recovery tests.
- Blockers/limitations: the requested enterprise product requires substantial engineering beyond this slice; production credentials, infrastructure, policy decisions and enterprise integrations have not been configured. Network and provider availability/rate limits apply.
- Next phase: prioritize authentication, authorization and tenant isolation with PostgreSQL migrations and an auditable data model before accepting sensitive data, followed by reliable collection and evidence workflows.

## Production readiness checklist (not met)

- [ ] Authenticated and authorized APIs, MFA, CSRF/session protection and tenant isolation.
- [ ] PostgreSQL schema migrations, access-controlled encrypted storage and secure secrets.
- [ ] Durable, tamper-resistant audit with retention and redaction policies.
- [ ] Adapter validation, retries, backoff, rate limiting and observability.
- [ ] Automated browser, accessibility, security, performance and tenant-isolation tests.
- [ ] Backup encryption, restore verification and documented RPO/RTO drills.
- [ ] Explicit security review, deployment runbooks and incident response procedures.
