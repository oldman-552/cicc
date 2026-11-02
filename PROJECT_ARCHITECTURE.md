# CICC project architecture

The authoritative detailed architecture is [docs/architecture/SYSTEM.md](docs/architecture/SYSTEM.md). This is a modular development foundation, not a completed enterprise design.

- React/TypeScript/Vite frontend: EN/AR/FA, RTL, explicit source/state labels, accessible list fallback for the illustrative 3D graph.
- Same-origin `/api` proxy to FastAPI; local accounts, coarse RBAC and development-only workspace scoping.
- SQLAlchemy/Alembic with SQLite by default and PostgreSQL validated for the baseline in a disposable CI service. Public source caches are global; private records are scoped in application queries. SQLite triggers / PostgreSQL foreign keys and triggers add limited guardrails; absent RLS, privileged DB access and incomplete relational constraints mean no production tenant-isolation claim.
- Fixed public GitHub advisory, CISA KEV, limited CVE Program and ATT&CK collectors; FIRST EPSS adapter is mocked-only and not live-verified. No automatic execution of downloaded content.
- Investigations, snapshots/checksums, mutable timeline and audit, user-attested assets and offline limited SBOM comparison. No proof of ownership, exposure, vulnerability or tamper resistance is inferred.

Critical missing dependencies: enforced enterprise MFA/SSO (optional local TOTP is available), production-grade isolation/authorization, secure evidence and audit, production deployment and recovery, comprehensive source coverage, most research and AI modules. Review `BLOCKERS.md` and `IMPLEMENTATION_TRACKER.md`.

- Development SQLite copy-to-new uses the SQLite backup API and integrity check; it does not encrypt, authenticate, cover PostgreSQL or invalidate restored sessions. See `docs/RECOVERY.md`.

- Trusted workspace disable/enable revokes workspace sessions transactionally. PostgreSQL login and account configuration acquire a workspace row lock first; this serializes workspace logins and is not load-tested. SQLite has no equivalent row locks; database triggers also revoke sessions for ordinary workspace state changes, but direct edits lack CLI audit and privileged database access can bypass safeguards.

- Selected investigation/SBOM child parent references have ORM checks and migration-installed immutability triggers. This cannot prevent delete/reinsert or prove prior ownership; PostgreSQL direct-SQL verification passed on a disposable CI database.

- The development SQLite restore-to-new operation stages the copy, checks its recorded revision and invalidates saved sessions before atomic publication; it does not authenticate backups, reconcile stale credentials or provide production recovery.

- Experimental SQLite encrypted backups use AES-256-GCM with protected plaintext staging and external backup keys; replay, stale security state, key custody and PostgreSQL recovery remain unresolved. No independent cryptographic review.

- Login and session validation fail closed on unknown role values; supported CLI account updates revoke sessions, database triggers also revoke on ordinary security-state changes, but direct edits lack CLI audit and privileged access can bypass safeguards.

- Migration c1af7842d90b restricts persisted role values via SQLite triggers / a PostgreSQL check, with preflight and guarded downgrade; PostgreSQL validation passed in disposable CI. Direct assignment of another valid role is not prevented.

- Migration ea2dd04051c8 adds transactional revocation triggers for ordinary account/workspace/MFA security-state changes and prevents security-record parent reassignment. Selected PostgreSQL checks passed in disposable CI; the selected direct workspace/login race test also passed in disposable CI. Not RLS or tamper-resistant audit.

- PostgreSQL asset metadata/status updates and link creation lock the asset row to serialize selected API races; selected PostgreSQL CI checks passed, SQLite concurrency remains uncertified.

- Global source cache writes are disabled by default outside demo and require both admin role and an explicit configured operator username. Caches remain shared and no enterprise operator governance or RLS is provided; PostgreSQL verification pending CI.
