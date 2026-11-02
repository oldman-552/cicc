# CICC master task queue

This is a prioritized working queue, not evidence that the complete RCTFC v4.1 specification was supplied to this checkout. The full original master prompt is not present in the repository; the session summary and `IMPLEMENTATION_TRACKER.md` preserve known requirements, but cannot prove full coverage. Do not invent requirements or declare completion on that basis.

## Active

1. Strengthen development workspace boundaries with database-side safeguards for scoped relationships and test migration/rollback and direct-SQL bypass scenarios. Preserve existing data; do not claim production isolation without comprehensive review and RLS.
2. Validate PostgreSQL and migration behavior in an actual disposable service/CI; monitor results if GitHub Actions are available.

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
