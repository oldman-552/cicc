# Development log

## 2026-11-02 — execution recovery files and security hardening session

- Recorded the known requirements, implemented scope, blockers, test baseline and next work in durable recovery files. The full original RCTFC v4.1 prompt is not present in the checkout; the queue is not represented as a complete transcription.
- Prior verified local baseline: 54 backend tests passed, 2 PostgreSQL tests skipped; 11 simulated-DOM tests passed; frontend build, SQLite schema check, pip check and npm audit passed. EPSS is mocked-only; Docker/PostgreSQL/real browser and production security remain unverified.
- Active next action: strengthen database-side workspace relationship safeguards, run migration and direct-SQL tests, and preserve all existing data.

### Database guard implementation

- Added migration `484b2e0f87f1` with online preflight, SQLite workspace/link triggers, and PostgreSQL workspace foreign keys and selected link/reassignment triggers. Existing inconsistent data causes migration failure before guards are created; no automatic repair or deletion. These are defense in depth, not RLS or certified tenant isolation.
- SQLite direct-SQL tests cover invalid references, cross-workspace links, moves, protected workspace deletion, migration refusal with legacy inconsistent data and downgrade/upgrade. Local development migration was repaired after an interrupted pre-release downgrade left partially removed triggers (SQLite DDL); no cached advisories were lost. Downgrade now tolerates interrupted trigger removal.
- Latest local result: 58 backend passed, 3 PostgreSQL tests skipped; 11 frontend tests passed; Vite build, Alembic check, pip check and npm audit passed. Three.js chunk warning remains.
- Prior baseline commit `e0a798c` passed GitHub Actions backend, frontend and disposable PostgreSQL jobs: https://github.com/oldman-552/cicc/actions/runs/41431454188. The new guard migration and new direct-SQL PostgreSQL test still require a successful new CI run.

### Identity operations and CI

- GitHub Actions run 41431887352 for commit `035e26f` passed backend, frontend and disposable PostgreSQL, including the new direct-SQL workspace guards: https://github.com/oldman-552/cicc/actions/runs/41431887352. This is not full concurrency/security certification.
- Added trusted-local account disabling with atomic session revocation and mutable workspace audit records for CLI account configuration, disabling and workspace creation. The actor `local-cli` is an unverified label and direct database changes bypass this audit. Re-enabling requires configuring a new password.
- New tests verify session invalidation, cross-workspace refusal, no password in audit/CLI output, transactional rollback and CLI behavior. Local suite: 63 passed, 4 PostgreSQL-only skipped. Added a PostgreSQL test; a new CI run is required.

### Optional local TOTP

- Account CLI commit `d26d7b2` passed GitHub Actions backend, frontend and disposable PostgreSQL: https://github.com/oldman-552/cicc/actions/runs/41432157576.
- Added optional local TOTP enrollment/reset CLI, AES-256-GCM encrypted seeds using an externally supplied stable key, one-time confirmation, session revocation, replay counter, login throttling integration and a six-digit input localized in EN/AR/FA. Enrollment and recovery are trusted-local operations, not self-service; MFA is not enforced and demo mode bypasses it.
- Added tests for encryption, wrong/missing keys failing closed, invalid/replayed codes, rollback, lockout, session revocation, password reset preserving MFA, migration downgrade refusal and localized UI. Added a disposable PostgreSQL concurrent replay test; its CI run is pending. Local tests: 68 backend passed, 5 PostgreSQL skipped; 12 simulated-DOM frontend tests passed; Alembic check, pip check, Vite build and npm audit passed.
