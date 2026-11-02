# Acceptance and verification record

The complete enterprise acceptance criteria are not yet satisfied. These commands verify only the implemented development slice:

```sh
.venv/bin/python -m pytest -q backend/tests
.venv/bin/alembic -c backend/alembic.ini check
.venv/bin/pip check
cd frontend && npm test && npm run build && npm audit --audit-level=high
```

Latest prior local results: backend 125 passed, 25 PostgreSQL-only skipped; frontend simulated DOM 13 passed; Vite build passed with a large Three.js chunk warning; schema check and pip check passed; npm audit reported zero vulnerabilities. No real-browser/WebGL/accessibility review, Docker run, local PostgreSQL integration run, live FIRST EPSS connection, external security assessment or DR exercise was verified locally. GitHub Actions baseline commit e0a798c passed backend, frontend and disposable PostgreSQL jobs: https://github.com/oldman-552/cicc/actions/runs/41431454188. Workspace-guard commit 035e26f also passed all jobs including direct-SQL PostgreSQL tests: https://github.com/oldman-552/cicc/actions/runs/41431887352. Account CLI commit d26d7b2 also passed: https://github.com/oldman-552/cicc/actions/runs/41432157576. Optional TOTP commit 31484af also passed, including the PostgreSQL replay-race test: https://github.com/oldman-552/cicc/actions/runs/41432791552. Enforcement commit adfcae2 passed: https://github.com/oldman-552/cicc/actions/runs/41433244922. Session-management commit a681b20 passed: https://github.com/oldman-552/cicc/actions/runs/41433664301. Readiness commit c50728f passed: https://github.com/oldman-552/cicc/actions/runs/41433984885. Offline rotation commit 14a904f passed: https://github.com/oldman-552/cicc/actions/runs/41434379208. SQLite copy commit dea68c2 passed: https://github.com/oldman-552/cicc/actions/runs/41434800817. Login/account-disable concurrency commit 455c8c3 passed: https://github.com/oldman-552/cicc/actions/runs/41435065254. Workspace lifecycle commit d087fce passed: https://github.com/oldman-552/cicc/actions/runs/41435452428, including the selected PostgreSQL login/deactivation race test. Scoped-link concurrency commit a2ad650 passed: https://github.com/oldman-552/cicc/actions/runs/41435722572. SQLite `alembic check` intentionally excludes workspace FK metadata because migration-installed triggers, not actual FKs, implement those checks; tests separately exercise the triggers. Results are not production certification.

Security acceptance requires at least verified isolation against API, direct-SQL and concurrency attacks on real supported databases; production identity including MFA; secure audit and evidence; secrets and operational hardening; tested backup/restore; and documented independent review. Data-source acceptance requires real authorized connectivity, correct provenance/freshness, robust failure behavior and explicit limitations. Do not equate mock tests with live integration.

Child parent guards and both sides of the asset–SBOM link/delete race are locally implemented; direct SQLite migration tests passed, PostgreSQL checks passed in disposable CI: https://github.com/oldman-552/cicc/actions/runs/41436533643. Historical reassignment, delete/reinsert and privileged SQL remain outside these guards.

Development SQLite restore-to-new session invalidation is tested with synthetic migrated data; That revision passed CI: https://github.com/oldman-552/cicc/actions/runs/41436843876. No production recovery claim.

Experimental authenticated SQLite backup tests cover encrypted round-trip, wrong key, header/nonce/ciphertext/tag tampering, truncation, output collision, size limit and acknowledgments using synthetic data; CI passed: https://github.com/oldman-552/cicc/actions/runs/41437204707. No external cryptographic review or production DR test.

Unexpected database role values are rejected for new logins and existing sessions in SQLite tests; PostgreSQL runtime check passed: https://github.com/oldman-552/cicc/actions/runs/41437432959. The subsequent role-guard migration passed disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41437758338. This does not certify authorization or database isolation.

Security-state change session-revocation and security parent-immutability migration has SQLite tests; PostgreSQL verification passed: https://github.com/oldman-552/cicc/actions/runs/41438149536. Direct-workspace/login race commit 52a917e passed: https://github.com/oldman-552/cicc/actions/runs/41438417897. Asset link/mutation concurrency checks passed: https://github.com/oldman-552/cicc/actions/runs/41438744913. In-flight requests, historical state, privileged database actions and SQLite concurrency remain limitations.

Explicit global-source operator policy is tested locally with synthetic workspaces, CSRF and three-language UI; PostgreSQL CI passed: https://github.com/oldman-552/cicc/actions/runs/41439176996. Global caches remain shared.

Source publication prevents older overlapping attempts from overwriting later completed results or errors in synthetic SQLite tests; ordering relies on application clocks, and PostgreSQL concurrency validation awaits CI.
