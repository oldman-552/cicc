# CICC master task queue

This is a prioritized working queue, not evidence that the complete RCTFC v4.1 specification was supplied to this checkout. The full original master prompt is not present in the repository; the session summary and `IMPLEMENTATION_TRACKER.md` preserve known requirements, but cannot prove full coverage. Do not invent requirements or declare completion on that basis.

## Active

1. Validate the local account disable/audit revision in disposable PostgreSQL CI and fix any failures.
2. Extend identity security toward MFA with secure key management, replay protection, rate limiting, recovery and tests; do not weaken existing authentication or expose secrets.
3. Continue adversarial workspace/concurrency testing; selected direct-SQL guards passed SQLite and disposable PostgreSQL CI, but production isolation and RLS remain absent.

## Pending — ordered by dependency, not approval gates

- Production identity: MFA, recovery, SSO, secure session lifecycle and hardened rate limiting.
- Tenant isolation: database-enforced boundaries, per-object authorization, threat modeling, adversarial/concurrency tests, secure operations.
- Audit, secret/key management, encryption, evidence integrity, retention and verified recovery.
- Source lifecycle, scheduling, NVD, OSV, research/news, full CVE/ATT&CK coverage, EPSS live verification and provenance.
- Investigations, evidence workflows, collaboration, search and notifications.
- Threat entities, relationships, graph and verifiable confidence/attribution.
- Authorized asset and exposure management, supply chain and cloud integrations.
- AI governance, model inventory, secured retrieval, agents and approval gates.
- Explainable recommendations, decision support, 3D/2D experience and controlled reporting/sharing.
- Real-browser accessibility/performance testing, production deployment, observability, CI/CD and disaster recovery.

See `IMPLEMENTATION_TRACKER.md` for precise implemented scope and `BLOCKERS.md` for unverified areas. Never fabricate integrations, evidence or test results; use only authorized defensive data.
