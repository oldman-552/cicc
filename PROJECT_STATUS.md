# CICC project status

**State: early development, not v1.0, not production-ready.** This project is a small functional slice of the much larger requested platform. The working tree is the source of truth. See the tracker for missing capabilities.

## Implemented in the development foundation

- React/TypeScript/Vite command center in English, Arabic and Persian, with RTL layout and explicit handling of technical identifiers.
- Four manual, public-source adapters: GitHub advisory metadata, the official CISA KEV GitHub mirror, limited CVE Program records, and a deterministic 10-file sample from MITRE ATT&CK STIX; source health, timestamps and retained cache on collection failure.
- Limited FIRST EPSS enrichment for up to 30 cached advisory CVEs, including model date and score on advisory and CVE lists; mocked responses only, live FIRST connection not verified.
- Cached advisory and KEV search, evidence snapshots, local investigations, analyst notes, JSON report, explicit reference graph with 3D and list fallback.
- Advisory snapshots include a same-database SHA-256 consistency check for new links; legacy snapshots have no recorded checksum, and matches are not proof of authenticity or tamper resistance.
- Paginated local investigation timeline, recorded transactionally from feature activation, not tamper-resistant and with no older-history backfill.
- Manual user-attested asset inventory, investigation snapshots and manually attested SBOM associations; no ownership verification, discovery, scanning or exposure assessment.
- Administrator activity view has cursor pagination and exact action filtering; logs are mutable and unscoped login failures are not shown.
- Local account CLI, scrypt passwords, expiring hashed sessions, CSRF tokens, simple roles and login throttling. Experimental application-level workspace scoping exists, but is not production tenant isolation or enterprise identity; public sources are global.
- Offline CycloneDX/SPDX JSON top-level SBOM import with package identity and conservative limited npm/PyPI stable-version comparisons; unsupported cases remain unknown, with no confirmation of vulnerability or guarantee of safety.
- Alembic schema migrations; SQLite development and PostgreSQL configuration; local non-tamper-resistant activity log; development Docker Compose files and CI workflow, neither run here.

## Verification performed

- SQLite upgrade with legacy records and an unsafe downgrade refusal tested; cross-workspace API tests passed. SQLite migrations applied; schema check passed. API/unit tests: 54 passed, 2 PostgreSQL-only tests skipped. UI simulated-DOM tests: 11 passed. TypeScript/Vite build passed; npm audit reported zero vulnerabilities at the time of checking.
- The live preview's Vite proxy served `/api/overview` and `/api/sboms`; a temporary synthetic SBOM was imported, compared against cached advisory identities, read back and removed; the limited CVE source was refreshed successfully. A temporary synthetic investigation was linked to a real cached ATT&CK reference and the graph through the proxy, then removed. A separate temporary synthetic asset was linked to an investigation and SBOM through the Vite proxy, checked in the graph and then removed. A temporary checksum, report and timeline flow was also checked through the proxy and removed. The local audit records the test actions.
- Last cached collection in the development database: 30 GitHub advisories, 1,766 CISA KEV records, 10 CVE Program records and 10 ATT&CK techniques. These are snapshots, not a live feed; the database is ignored by Git and is not part of the deliverable.
- No visual real-browser or WebGL validation, accessibility audit, PostgreSQL integration run (including the newly defined scope and downgrade guard test), Docker run, CI execution, penetration test, load test or disaster recovery drill was performed.
- The lazily loaded Three.js chunk is about 901 kB minified and triggers a Vite size warning. A Starlette/anyio deprecation warning appears in backend tests.

## Known boundaries

The preview disables authentication and must not contain sensitive data. No MFA, tenant isolation, production-grade authorization, encrypted vault, trusted/tamper-evident audit, SSO, production deployment or enterprise operational controls are present. NVD, OSV and research/news adapters; live verification and broader coverage for EPSS and comprehensive CVE ingestion; advanced research, threat/actor/malware/campaign intelligence; authorized discovery and asset exposure assessment, full supply-chain and cloud posture; AI governance/agents; full 3D universe; and many other requested capabilities remain unimplemented.
