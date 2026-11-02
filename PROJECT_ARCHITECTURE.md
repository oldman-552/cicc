# CICC project architecture

The authoritative detailed architecture is [docs/architecture/SYSTEM.md](docs/architecture/SYSTEM.md). This is a modular development foundation, not a completed enterprise design.

- React/TypeScript/Vite frontend: EN/AR/FA, RTL, explicit source/state labels, accessible list fallback for the illustrative 3D graph.
- Same-origin `/api` proxy to FastAPI; local accounts, coarse RBAC and development-only workspace scoping.
- SQLAlchemy/Alembic with SQLite by default and PostgreSQL validated for the baseline in a disposable CI service. Public source caches are global; private records are scoped in application queries. SQLite triggers / PostgreSQL foreign keys and triggers add limited guardrails; absent RLS, privileged DB access and incomplete relational constraints mean no production tenant-isolation claim.
- Fixed public GitHub advisory, CISA KEV, limited CVE Program and ATT&CK collectors; FIRST EPSS adapter is mocked-only and not live-verified. No automatic execution of downloaded content.
- Investigations, snapshots/checksums, mutable timeline and audit, user-attested assets and offline limited SBOM comparison. No proof of ownership, exposure, vulnerability or tamper resistance is inferred.

Critical missing dependencies: enforced enterprise MFA/SSO (optional local TOTP is available), production-grade isolation/authorization, secure evidence and audit, production deployment and recovery, comprehensive source coverage, most research and AI modules. Review `BLOCKERS.md` and `IMPLEMENTATION_TRACKER.md`.

- Development SQLite copy-to-new uses the SQLite backup API and integrity check; it does not encrypt, authenticate, cover PostgreSQL or invalidate restored sessions. See `docs/RECOVERY.md`.

- Trusted workspace disable/enable revokes workspace sessions transactionally. PostgreSQL login and account configuration acquire a workspace row lock first; this serializes workspace logins and is not load-tested. SQLite has no equivalent row locks, and direct SQL state edits bypass this workflow.

- Selected investigation/SBOM child parent references have ORM checks and migration-installed immutability triggers. This cannot prevent delete/reinsert or prove prior ownership; PostgreSQL direct-SQL verification passed on a disposable CI database.

- The development SQLite restore-to-new operation stages the copy, checks its recorded revision and invalidates saved sessions before atomic publication; it does not authenticate backups, reconcile stale credentials or provide production recovery.

- Experimental SQLite encrypted backups use AES-256-GCM with protected plaintext staging and external backup keys; replay, stale security state, key custody and PostgreSQL recovery remain unresolved. No independent cryptographic review.
