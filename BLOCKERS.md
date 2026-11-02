# Blockers and unverified areas

| Item | State | Effect / next action |
|---|---|---|
| Docker | Unavailable in this environment | Dockerfiles/Compose are untested; validate image builds, networking, persistent volume behavior and PostgreSQL migrations where Docker is available. |
| PostgreSQL | Baseline passed on disposable GitHub Actions PostgreSQL, not run locally | Selected guard operations passed in disposable PostgreSQL CI; concurrency behavior requires validation; continue comprehensive isolation, migration and recovery testing. |
| Browser/WebGL | No real visual browser verification performed | Test desktop/mobile layouts, RTL, keyboard use, WebGL rendering/fallback, performance and accessibility. |
| Production identity/security | Not implemented | Phishing-resistant and enterprise-managed MFA (local TOTP policy exists), SSO, production tenant boundaries (experimental application-level scope is not sufficient), fine-grained permissions, immutable audit, secrets, encrypted evidence, production-grade traffic/body controls and independent security assessment are required. |
| Asset authorization | User-attested only; no independent ownership verification or production tenant isolation | Do not treat recorded scope, SBOM links or graph links as evidence of authorization, deployment or exposure. |
| Data coverage | Most requested public adapters not implemented | GitHub/CISA/CVE Program/ATT&CK are manual cached snapshots; ATT&CK is a 10-file sample; CVE collection is a limited selection, not a full feed. FIRST EPSS adapter is mocked-only; live endpoint is outside allowed outbound hosts. Add and validate NVD, OSV and other authorized sources. |
| Private services | Credentials/authorization not supplied | Only required when implementing specific private integrations. Do not solicit or store credentials in chat; continue unrelated development. |
| CI | Baseline, workspace-guard, account CLI and optional TOTP GitHub Actions runs passed; TOTP enforcement and session-management revisions passed; readiness revision passed; offline key rotation revision passed; SQLite copy, account login/disable, workspace lifecycle and child-parent guard revisions passed; development restore revision passed; encrypted SQLite backup revision passed; invalid role rejection revision pending | Add comprehensive security, browser, concurrency and recovery jobs. |
| Investigation timeline | Local mutable table, no older-history backfill | Do not treat it as a tamper-evident audit trail or chain of custody. |
| Backup/DR | No implementation or drill | Design protected backups, restoration testing and measurable RPO/RTO before deployment. |
| SBOM precision | Only a limited npm/PyPI range subset is evaluated; JSON parsing is not isolated | Candidate identity matches cannot establish vulnerability or safety; add isolated parsing and broaden ecosystem-correct range evaluation. |
| Bundle size | Vite reports large lazy-loaded Three.js chunk (~901 kB minified) | Measure real browser performance and optimize without misrepresenting results. |

- Direct database workspace deactivation bypasses the audited CLI and can revive unexpired sessions on reactivation. Selected PostgreSQL CLI lifecycle concurrency checks passed in disposable CI; SQLite concurrent login/lifecycle safety is not certified.

- Child-parent immutability guard and asset–SBOM concurrency passed disposable PostgreSQL CI; it cannot prevent privileged SQL or delete/reinsert and is not RLS.

- Experimental authenticated encrypted SQLite backups require protected plaintext staging and external keys; anti-rollback, authenticated key custody, independent cryptographic review, PostgreSQL recovery and production DR drills are absent.
