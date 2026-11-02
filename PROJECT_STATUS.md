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
- SQLite triggers and PostgreSQL foreign keys/triggers guard selected workspace references and links after migration preflight; SQLite and disposable PostgreSQL CI direct-SQL tests passed. These are not production tenant isolation.
- Local TOTP enrollment via trusted CLI and a session-security view with self-service revocation of other sessions, AES-GCM-protected seeds, replay counter and session revocation; deployment-wide enforcement is available but off by default; not phishing-resistant and dependent on an external key.
- Local account CLI with disabling, session revocation and mutable unverified local-cli audit records; scrypt passwords, expiring hashed sessions, CSRF tokens, simple roles and login throttling. Experimental application-level workspace scoping exists, but is not production tenant isolation or enterprise identity; public sources are global.
- Offline CycloneDX/SPDX JSON top-level SBOM import with package identity and conservative limited npm/PyPI stable-version comparisons; unsupported cases remain unknown, with no confirmation of vulnerability or guarantee of safety.
- Alembic schema migrations; SQLite development and PostgreSQL configuration; local non-tamper-resistant activity log; development Docker Compose files (not run locally) and CI workflow.

## Verification performed

- SQLite upgrade with legacy records and an unsafe downgrade refusal tested; cross-workspace API tests passed. SQLite migrations applied; schema check passed. API/unit tests: 75 passed, 7 PostgreSQL-only tests skipped. UI simulated-DOM tests: 12 passed. TypeScript/Vite build passed; npm audit reported zero vulnerabilities at the time of checking.
- The live preview's Vite proxy served `/api/overview` and `/api/sboms`; a temporary synthetic SBOM was imported, compared against cached advisory identities, read back and removed; the limited CVE source was refreshed successfully. A temporary synthetic investigation was linked to a real cached ATT&CK reference and the graph through the proxy, then removed. A separate temporary synthetic asset was linked to an investigation and SBOM through the Vite proxy, checked in the graph and then removed. A temporary checksum, report and timeline flow was also checked through the proxy and removed. The local audit records the test actions.
- Last cached collection in the development database: 30 GitHub advisories, 1,766 CISA KEV records, 10 CVE Program records and 10 ATT&CK techniques. These are snapshots, not a live feed; the database is ignored by Git and is not part of the deliverable.
- GitHub Actions baseline commit e0a798c passed backend, frontend and disposable PostgreSQL jobs ([run 41431454188](https://github.com/oldman-552/cicc/actions/runs/41431454188)); workspace-guard commit 035e26f also passed all three jobs including PostgreSQL direct-SQL guards ([run 41431887352](https://github.com/oldman-552/cicc/actions/runs/41431887352)); account CLI commit d26d7b2 also passed ([run 41432157576](https://github.com/oldman-552/cicc/actions/runs/41432157576)); optional TOTP commit 31484af also passed including its PostgreSQL concurrent replay test ([run 41432791552](https://github.com/oldman-552/cicc/actions/runs/41432791552)); the enforcement policy commit adfcae2 passed, including PostgreSQL ([run 41433244922](https://github.com/oldman-552/cicc/actions/runs/41433244922)); subsequent session-management changes require their own CI run. No local PostgreSQL or Docker run, real-browser/WebGL validation, accessibility audit, penetration test, load test or disaster recovery drill was performed.
- The lazily loaded Three.js chunk is about 901 kB minified and triggers a Vite size warning. A Starlette/anyio deprecation warning appears in backend tests.

## Known boundaries

The preview disables authentication and must not contain sensitive data. No enforced enterprise MFA, production tenant isolation, production-grade authorization, encrypted evidence vault, trusted/tamper-evident audit, SSO, production deployment or enterprise operational controls are present. NVD, OSV and research/news adapters; live verification and broader coverage for EPSS and comprehensive CVE ingestion; advanced research, threat/actor/malware/campaign intelligence; authorized discovery and asset exposure assessment, full supply-chain and cloud posture; AI governance/agents; full 3D universe; and many other requested capabilities remain unimplemented.
