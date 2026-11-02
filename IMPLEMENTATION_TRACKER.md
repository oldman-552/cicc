# Implementation tracker

This is a thematic dependency map of the requested platform, **not a claim that the full specification is represented or implemented**. Stages are organizational dependencies, not approval gates. Status: **Partial** means the narrow current behavior only; **Missing** means no functional implementation. Nothing here is certified production-ready.

| Stage | Capability | Status | Current behavior / remaining work |
|---|---|---|---|
| 1 | Core application and localization | Partial | React/Vite + FastAPI, EN/AR/FA and RTL; broaden localization and real-browser/accessibility testing. |
| 1 | Persistence and migrations | Partial | SQLite migrations applied; baseline and workspace-guard PostgreSQL integration passed in disposable CI; Compose not tested. |
| 1 | Identity, roles and sessions | Partial | Local accounts, scrypt, hashed sessions, CSRF, basic roles/throttling, audited trusted-local account and workspace disable/session revocation; local TOTP with encrypted secrets, replay rejection, optional deployment-wide enforcement and offline key rotation, session self-revocation, no phishing-resistant MFA, SSO or production controls. |
| 1 | Tenant isolation and fine-grained authorization | Partial | Experimental application-level workspace scoping and adversarial API tests; global source cache, database guards for selected relationships, no RLS or comprehensive constraints, no production isolation. |
| 1 | Secure audit and secrets | Partial | Local activity entries with workspace-scoped admin pagination/filtering; unscoped auth failures omitted; no append-only protection, key management or secret vault. |
| 2 | Source registry and provenance | Partial | Five fixed adapters, timestamps, status and cached source references; no generic registry, scheduling or connector lifecycle. |
| 2 | GitHub advisories | Partial | Latest 30 returned per manual refresh; no full historical ingest or resilient incremental synchronization. |
| 2 | CISA KEV | Partial | Official GitHub mirror, blob hash/shape validation and snapshot replacement; not independent signature verification. |
| 2 | CVE Program records | Partial | Up to 10 CVEs from cached advisories fetched manually from the official repository with blob checks; not a complete CVE feed. |
| 2 | MITRE ATT&CK | Partial | Deterministic sample of 10 STIX technique files from MITRE CTI; explicit reference links only, no activity or attribution inference. |
| 2 | FIRST EPSS | Partial | Limited current scores for up to 30 cached advisory CVEs; validated with mocked responses only, live endpoint inaccessible in this environment. |
| 2 | NVD and OSV | Missing | Implement real adapters, quotas, source-specific validation and freshness policies. |
| 2 | Research/news and commercial/authorized sources | Missing | Implement adapters, access controls, licenses and provenance. |
| 3 | Investigations and collaboration | Partial | Workspace-scoped local investigations, statuses, snapshots, notes and non-tamper-resistant timeline; missing assignments, workflow and collaboration. |
| 3 | Evidence management | Partial | Source metadata snapshots, classifications and same-database advisory checksum for new links; no tamper-proof evidence vault, chain of custody, attachments or retention controls. |
| 3 | Search, notifications and alerts | Partial | Cached advisory/KEV search; no federated search, rules, subscriptions or notifications. |
| 4 | Knowledge graph and confidence | Partial | Explicit investigation-to-advisory, ATT&CK technique and user-attested asset snapshot references with unknown confidence; no broad entity model, graph inference, verification or graph DB. |
| 4 | Threat actors, malware and campaigns | Missing | No research modules, linkage, attribution or temporal analysis. |
| 4 | Vulnerability intelligence | Partial | GitHub advisories, KEV and limited CVE Program records; no comprehensive CVE normalization, prioritization or exploitability assessment. |
| 5 | SBOM and software supply chain | Partial | Offline JSON metadata import, purl-based candidate identities; limited npm/PyPI stable-version subset comparison only; no complete version evaluation, dependency graph, supplier risk or continuous rescanning. |
| 5 | Authorized assets and exposure | Partial | Manual user-attested inventory, metadata editing, investigation snapshots and SBOM association; no independently verified authorization, production tenant isolation, discovery, scanning or exposure assessment. |
| 5 | Cloud and enterprise integrations | Missing | No cloud posture ingestion, connectors, authorized asset mapping or enterprise APIs. |
| 6 | AI models and governance | Missing | No model registry, access controls, evaluation, model audit, policy, or prompt-injection mitigations. |
| 6 | AI agents, retrieval and approvals | Missing | No agents, RAG, workflows, approval gates or automatic actions. |
| 7 | Recommendations and impact simulation | Missing | No explainable risk recommendations, simulations or decision support. |
| 7 | 3D universe and 2D fallback | Partial | A lazy-loaded illustrative reference graph and accessible list; no full universe, geographic intelligence or real-browser validation. |
| 7 | Reporting and controlled sharing | Partial | JSON investigation export only; no templates, sharing policy, redaction, scheduled or signed reports. |
| 8 | APIs and integration | Partial | Documented development API; no versioning, enterprise integration or SDK contract guarantees. |
| 9 | Tests and security assurance | Partial | Unit/API security and simulated DOM checks; PostgreSQL flow, workspace/downgrade and selected direct-SQL guards passed in disposable CI; account changes passed in disposable CI, optional TOTP PostgreSQL race test passed; enforcement policy PostgreSQL check passed; session revocation check passed; readiness check passed; offline rotation PostgreSQL test passed; development SQLite copy test passed; login/disable race test passed; selected workspace lifecycle and investigation–asset link/deletion race tests passed in PostgreSQL CI; child-parent guards and asset–SBOM race tests passed in disposable PostgreSQL CI; development SQLite restore-to-new passed CI; experimental encrypted backup passed CI; unknown-role fail-closed PostgreSQL check passed; database role-guard migration passed; security-state revocation triggers pending PostgreSQL CI. Limited cross-workspace SQLite API tests; no visual browser, accessibility or comprehensive security/load and isolation assurance. |
| 10 | CI/CD | Partial | Development CI definition created but not run here; no verified releases, artifact signing or deployment pipeline. |
| 11 | Deployment and observability | Partial | Development Dockerfiles and Compose added but untested; liveness and limited database/identity readiness probes implemented; SQLite development copy/verify-to-new utility only; no PostgreSQL backup, production recovery, production topology, monitoring, tracing or operational hardening. |
| 12 | Backup and recovery | Missing | No automated backup, validated restore, RPO/RTO or recovery drill. |

Across all stages: enforce legal/authorized defensive scope, preserve data lineage and classifications, and never invent data, evidence or successful integrations.
