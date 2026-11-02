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
- Trusted CLI workspace disable/enable revokes workspace sessions; selected PostgreSQL lifecycle concurrency checks passed in disposable CI, and ordinary workspace state edits also trigger session revocation after the new migration; direct edits are not audited.
- Local TOTP enrollment via trusted CLI and a session-security view with self-service revocation of other sessions, AES-GCM-protected seeds, replay counter and session revocation; deployment-wide enforcement is available but off by default; offline key rotation requires operator-managed downtime and is not production-certified; not phishing-resistant and dependent on an external key.
- Local account CLI with disabling, session revocation and mutable unverified local-cli audit records; scrypt passwords, expiring hashed sessions, CSRF tokens, simple roles and login throttling. Experimental application-level workspace scoping exists, but is not production tenant isolation or enterprise identity; public sources are global.
- Offline CycloneDX/SPDX JSON top-level SBOM import with package identity and conservative limited npm/PyPI stable-version comparisons; unsupported cases remain unknown, with no confirmation of vulnerability or guarantee of safety.
- Development SQLite copy/verify-to-new-file, tested only with synthetic data; snapshots can restore revoked sessions and require separately secured MFA keys. No PostgreSQL backup or production recovery.
- Liveness and limited database/identity/MFA-key readiness endpoints; they do not certify deployment readiness.
- Alembic schema migrations; SQLite development and PostgreSQL configuration; local non-tamper-resistant activity log; development Docker Compose files (not run locally) and CI workflow.

## Verification performed

- SQLite upgrade with legacy records and an unsafe downgrade refusal tested; cross-workspace API tests passed. SQLite migrations applied; schema check passed. API/unit tests: 127 passed, 26 PostgreSQL-only tests skipped. UI simulated-DOM tests: 13 passed. TypeScript/Vite build passed; npm audit reported zero vulnerabilities at the time of checking.
- The live preview's Vite proxy served `/api/overview` and `/api/sboms`; a temporary synthetic SBOM was imported, compared against cached advisory identities, read back and removed; the limited CVE source was refreshed successfully. A temporary synthetic investigation was linked to a real cached ATT&CK reference and the graph through the proxy, then removed. A separate temporary synthetic asset was linked to an investigation and SBOM through the Vite proxy, checked in the graph and then removed. A temporary checksum, report and timeline flow was also checked through the proxy and removed. The local audit records the test actions.
- Last cached collection in the development database: 30 GitHub advisories, 1,766 CISA KEV records, 10 CVE Program records and 10 ATT&CK techniques. These are snapshots, not a live feed; the database is ignored by Git and is not part of the deliverable.
- GitHub Actions baseline commit e0a798c passed backend, frontend and disposable PostgreSQL jobs ([run 41431454188](https://github.com/oldman-552/cicc/actions/runs/41431454188)); workspace-guard commit 035e26f also passed all three jobs including PostgreSQL direct-SQL guards ([run 41431887352](https://github.com/oldman-552/cicc/actions/runs/41431887352)); account CLI commit d26d7b2 also passed ([run 41432157576](https://github.com/oldman-552/cicc/actions/runs/41432157576)); optional TOTP commit 31484af also passed including its PostgreSQL concurrent replay test ([run 41432791552](https://github.com/oldman-552/cicc/actions/runs/41432791552)); the enforcement policy commit adfcae2 passed, including PostgreSQL ([run 41433244922](https://github.com/oldman-552/cicc/actions/runs/41433244922)); session-management commit a681b20 passed ([run 41433664301](https://github.com/oldman-552/cicc/actions/runs/41433664301)); readiness commit c50728f passed ([run 41433984885](https://github.com/oldman-552/cicc/actions/runs/41433984885)); offline key rotation commit 14a904f passed ([run 41434379208](https://github.com/oldman-552/cicc/actions/runs/41434379208)); SQLite copy commit dea68c2 passed ([run 41434800817](https://github.com/oldman-552/cicc/actions/runs/41434800817)); account login/disable concurrency commit 455c8c3 passed ([run 41435065254](https://github.com/oldman-552/cicc/actions/runs/41435065254)); workspace lifecycle commit d087fce passed ([run 41435452428](https://github.com/oldman-552/cicc/actions/runs/41435452428)); scoped-link concurrency commit a2ad650 passed ([run 41435722572](https://github.com/oldman-552/cicc/actions/runs/41435722572)). No local PostgreSQL or Docker run, real-browser/WebGL validation, accessibility audit, penetration test, load test or disaster recovery drill was performed.
- The lazily loaded Three.js chunk is about 901 kB minified and triggers a Vite size warning. A Starlette/anyio deprecation warning appears in backend tests.

## Known boundaries

The preview disables authentication and must not contain sensitive data. No enforced enterprise MFA, production tenant isolation, production-grade authorization, encrypted evidence vault, trusted/tamper-evident audit, SSO, production deployment or enterprise operational controls are present. NVD, OSV and research/news adapters; live verification and broader coverage for EPSS and comprehensive CVE ingestion; advanced research, threat/actor/malware/campaign intelligence; authorized discovery and asset exposure assessment, full supply-chain and cloud posture; AI governance/agents; full 3D universe; and many other requested capabilities remain unimplemented.

- Child parent immutability guards are tested on migrated SQLite; PostgreSQL guard and asset–SBOM race tests passed in disposable CI ([run 41436533643](https://github.com/oldman-552/cicc/actions/runs/41436533643)). Not RLS or production isolation.

- Development SQLite restore-to-new invalidates saved sessions and checks recorded migration revision; backup authenticity, stale credentials and production recovery remain unresolved; CI passed for the session-invalidating restore ([run 41436843876](https://github.com/oldman-552/cicc/actions/runs/41436843876)).

- Experimental AES-256-GCM SQLite backup/restore with external key and protected plaintext staging passed synthetic tests and CI ([run 41437204707](https://github.com/oldman-552/cicc/actions/runs/41437204707)); no key custody, anti-rollback, independent security review or PostgreSQL recovery.

- Unexpected identity roles now fail closed for login and existing sessions; runtime PostgreSQL check passed ([run 41437432959](https://github.com/oldman-552/cicc/actions/runs/41437432959)); the subsequent database role-guard migration passed ([run 41437758338](https://github.com/oldman-552/cicc/actions/runs/41437758338)).

- SQLite migration tests pass for automatic session revocation on identity/workspace/MFA changes and parent immutability; PostgreSQL direct-SQL validation passed ([run 41438149536](https://github.com/oldman-552/cicc/actions/runs/41438149536)); the direct-workspace/login race test also passed ([run 41438417897](https://github.com/oldman-552/cicc/actions/runs/41438417897)).

- Asset mutation/link API requests now lock the asset row on PostgreSQL; selected race tests passed in disposable CI ([run 41438744913](https://github.com/oldman-552/cicc/actions/runs/41438744913)) and SQLite concurrency remains uncertified.

- Global source refresh requires explicitly configured admin operators outside demo; caches remain shared, and PostgreSQL validation passed ([run 41439176996](https://github.com/oldman-552/cicc/actions/runs/41439176996)).

- Superseded source refreshes no longer overwrite a later completed attempt; the original PostgreSQL concurrency tests passed ([run 41439546375](https://github.com/oldman-552/cicc/actions/runs/41439546375)). New database-issued sequence ordering removes clock dependence but awaits PostgreSQL CI.
