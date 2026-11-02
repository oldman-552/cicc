# System architecture

```text
Browser (React/TypeScript/Vite, English/Arabic/Persian, WebGL + accessible list)
    | same-origin /api
    v
FastAPI modular application — local accounts, coarse roles, experimental workspace scoping
    |                       |
    v                       v
SQLAlchemy + Alembic        fixed public GitHub and FIRST API endpoints
SQLite dev / PostgreSQL     GitHub advisories; CISA KEV mirror; limited CVE Program and ATT&CK records; mocked-only FIRST EPSS adapter
```

Data flow: public source → validated source-reported cached advisory/catalog → analyst-created investigation → immutable-at-link-time metadata snapshot and classified note → explicit reference graph and JSON report. SBOM package identities and a limited npm/PyPI stable-version subset are compared against cached advisories; a range match is not a confirmed vulnerability. Assets and their investigation/SBOM links are user-attested and unverified; none constitutes proof of authorization, deployment or exposure. No asset network access is performed. New advisory snapshots have same-database checksums for consistency, not authenticity or tamper resistance; legacy snapshots remain unknown. Source refresh never executes downloaded content. The illustrated globe is synthetic and separate from actual reference data.

## Current data model

Users, hashed sessions, login attempts, sources, advisories, KEV entries, investigations, evidence snapshots, notes, local timeline events, ATT&CK techniques and references, SBOMs, SBOM components, SBOM candidate snapshots, manually attested assets, investigation-asset and asset-SBOM links, and audit events have Alembic migrations. Protected root records use workspace identifiers and application-level query/link checks; a migration adds SQLite triggers and PostgreSQL foreign keys/triggers for workspace references, immutable root scopes and two scoped link types. Public sources are shared globally. These checks do not constitute production tenant isolation. PostgreSQL is supported by SQLAlchemy and a Compose configuration; baseline and workspace-guard CI ran against disposable PostgreSQL; production behavior is not certified. SQLite foreign keys are enabled.

## API contracts

FastAPI exposes interactive documentation at `/docs` and `/openapi.json`.

- `/api/auth/session`, `/api/auth/login`, `/api/auth/logout`: local session management.
- `/api/sources`, `/api/sources/{github|cisa|mitre|attack|epss}/refresh`: manual collection, health and freshness.
- `/api/advisories`, `/api/kev`, `/api/cves`: paginated cached search, source labels and CVE-level KEV correlation. Advisories may include limited cached EPSS model estimates; the FIRST adapter is mocked-only, not live-verified. CVE Program collection is limited to at most 10 CVEs referenced by cached GitHub advisories per refresh.
- `/api/techniques`: a deterministic sample of 10 official MITRE ATT&CK STIX technique files, not a comprehensive feed.
- `/api/overview`: database-derived counts.
- `/api/investigations`, `/api/investigations/{id}`, `/evidence`, `/notes`, `/assets`, `/techniques`, `/timeline`, `/report`: local investigation lifecycle.
- `/api/graph`: up to 300 explicit investigation-to-evidence references, 300 investigation-to-asset references, and 300 ATT&CK technique references; no inferred attribution or exposure.
- `/api/assets`, `/api/assets/{id}`, `/api/investigations/{id}/assets`, `/api/assets/{id}/sboms`: manual, unverified inventory and links; no scanning.
- `/api/sboms`, `/api/sboms/{id}`: limited offline metadata import, package candidates and conservative version-comparison snapshots (see `docs/SBOM.md`).
- `/api/audit`, `/api/audit/events`: admin-only mutable workspace activity; paginated/filterable events omit unscoped login failures.

## Security boundaries and limitations

Local accounts use scrypt, random hashed session/CSRF tokens, secure HttpOnly session cookies, coarse server-side roles and basic login throttling. `CICC_DEMO_MODE=1` explicitly bypasses all authentication. Roles share data within their development workspace; public source caches and refreshes are global. Unknown or inactive-account login failures generate unscoped audit records not visible through workspace audit; known active-account failures are attributed to their workspace. Rate limiting is SQLite/database-backed and is not distributed or concurrency-hardened; a proxy can cause users to share a limit. Audit is not append-only or tamper-resistant. There is no MFA, SSO, production tenant isolation, per-object policy, encrypted data storage or production key management. SBOM requests have a 1,100,000-byte HTTP envelope limit before JSON parsing and a 1 MiB document check after parsing; other API POST/PUT/PATCH bodies have a 64 KiB envelope limit, and public-source responses are capped at 16 MiB of decoded data; these limits are not an isolated document parser or complete denial-of-service protection.

## Dependency map

1. Identity, organization/workspace boundaries, authorization, migrations, audit and retention.
2. Source registry, resilient adapters, scheduling, rate controls, normalized records and provenance.
3. Evidence, scoped investigations, search, alerts and analyst collaboration.
4. Evidence-backed entities, relationships, confidence and graph traversal.
5. Authorized asset scope, research, cloud, SBOM and supplier intelligence.
6. AI model registry, constrained retrieval and agents, approval gates and evidence-governed outputs.
7. Decision support, impact simulation, production 3D/2D, reporting and controlled sharing.
8. Observability, tests, backups, recovery drills and deployment readiness throughout.

Only the parts explicitly documented as implemented are present. No automatic asset scanning, exploitation, external URL execution or malware execution exists.
