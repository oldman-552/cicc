# CICC project architecture

The authoritative detailed architecture is [docs/architecture/SYSTEM.md](docs/architecture/SYSTEM.md). This is a modular development foundation, not a completed enterprise design.

- React/TypeScript/Vite frontend: EN/AR/FA, RTL, explicit source/state labels, accessible list fallback for the illustrative 3D graph.
- Same-origin `/api` proxy to FastAPI; local accounts, coarse RBAC and development-only workspace scoping.
- SQLAlchemy/Alembic with SQLite by default and PostgreSQL validated for the baseline in a disposable CI service. Public source caches are global; private records are scoped in application queries. SQLite triggers / PostgreSQL foreign keys and triggers add limited guardrails; absent RLS, privileged DB access and incomplete relational constraints mean no production tenant-isolation claim.
- Fixed public GitHub advisory, CISA KEV, limited CVE Program and ATT&CK collectors; FIRST EPSS adapter is mocked-only and not live-verified. No automatic execution of downloaded content.
- Investigations, snapshots/checksums, mutable timeline and audit, user-attested assets and offline limited SBOM comparison. No proof of ownership, exposure, vulnerability or tamper resistance is inferred.

Critical missing dependencies: enforced enterprise MFA/SSO (optional local TOTP is available), production-grade isolation/authorization, secure evidence and audit, production deployment and recovery, comprehensive source coverage, most research and AI modules. Review `BLOCKERS.md` and `IMPLEMENTATION_TRACKER.md`.
