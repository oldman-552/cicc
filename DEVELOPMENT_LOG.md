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

### TOTP enforcement and session assurance

- Optional TOTP commit `31484af` passed GitHub Actions backend, frontend and disposable PostgreSQL, including concurrent replay rejection: https://github.com/oldman-552/cicc/actions/runs/41432791552. This is not enterprise security certification.
- Added opt-in `CICC_REQUIRE_MFA=1` deployment-wide policy; invalid configuration fails startup. Added a migration that marks prior sessions MFA-unverified; enrolled accounts always reject sessions without TOTP, and the enforcement switch additionally blocks password-only accounts and sessions. Migration downgrade is refused while MFA enrollments exist. Demo mode intentionally bypasses both authentication and policy.
- New tests cover policy activation, pre-existing/unverified sessions, reset revocation, failed enrollment, migration preservation and invalid configuration; a PostgreSQL policy test is defined for the next CI run. Latest local results: 73 backend passed, 6 PostgreSQL-only skipped; 12 frontend tests, Vite build, SQLite schema check, pip check and npm audit passed.

### Session management

- TOTP enforcement commit `adfcae2` passed GitHub Actions backend, frontend and disposable PostgreSQL: https://github.com/oldman-552/cicc/actions/runs/41433244922.
- Added a CSRF-protected self-service action to revoke an account’s other sessions, including viewer accounts, without affecting the current session or other accounts. The authenticated status page shows TOTP enrollment and deployment policy; it does not claim production security. Demo mode has no session management. In-flight requests may still complete.
- Local results: 75 backend passed, 7 PostgreSQL-only tests skipped; 12 frontend tests passed; build, Alembic check, pip check and npm audit passed. PostgreSQL session-revocation validation is defined for the next CI run.

### Development readiness probe

- Session-management commit `a681b20` passed GitHub Actions backend, frontend and disposable PostgreSQL: https://github.com/oldman-552/cicc/actions/runs/41433664301.
- Added public liveness-independent `/api/ready` with database/limited identity-schema checks and, when relevant, validation of the MFA key against one enrolled seed. Failures return only a generic 503. The proposed Compose health check now uses it; Docker remains untested. This probe is not comprehensive migration, security or deployment readiness certification.
- Local results: 78 backend passed, 7 PostgreSQL-only skipped; frontend tests/build, schema check, pip check and npm audit remain passed. A PostgreSQL readiness check is included in the next CI run.

### Offline MFA key rotation

- Readiness commit `c50728f` passed GitHub Actions backend, frontend and disposable PostgreSQL: https://github.com/oldman-552/cicc/actions/runs/41433984885.
- Added global, offline-only MFA seed key rotation with operator downtime acknowledgment, bounded enrollment count, validation before mutation, one database transaction, per-workspace mutable audit counts and session revocation. The tool cannot verify downtime, distribute secrets, or resolve an uncertain commit automatically. No production recovery/rotation drill is claimed.
- Tests cover multi-workspace rotation, failed decryption, transaction rollback, no key in output and CLI scope validation. Local result: 82 backend passed, 8 PostgreSQL skipped; 12 frontend tests, build, schema check, pip check and npm audit passed. A PostgreSQL rotation test is pending CI.

### SQLite development copy and recovery limitations

- Offline MFA key rotation commit `14a904f` passed GitHub Actions backend, frontend and disposable PostgreSQL, including the rotation test: https://github.com/oldman-552/cicc/actions/runs/41434379208.
- Added a trusted-local SQLite copy-to-new/verify CLI with exclusive creation, owner-only permissions, integrity checking and cleanup of partial files on handled failures. Tests cover committed WAL data, no-overwrite and symlink behavior, application identity data in a restored synthetic snapshot, and session revival. It is unencrypted, not authenticating, does not include MFA keys or support PostgreSQL, and is not a production backup/recovery solution.
- Local result: 87 backend passed, 8 PostgreSQL skipped; 12 frontend tests, build, schema check, pip check and npm audit passed. CI for the SQLite copy revision is pending.

### PostgreSQL login/disable race test and workspace caveat

- SQLite copy commit `dea68c2` passed GitHub Actions backend, frontend and disposable PostgreSQL: https://github.com/oldman-552/cicc/actions/runs/41434800817.
- Added a PostgreSQL-only test exercising both login-before-disable and disable-before-login ordering; validation requires the next CI run. Corrected documentation: directly deactivating a workspace blocks sessions only while inactive and may revive them on reactivation. Migrations require stopped writers; no safe workspace lifecycle workflow is claimed.
- Local results remain 87 backend passed, 9 PostgreSQL skipped; frontend 12 passed, build/schema/pip checks and npm audit passed previously.

### Trusted workspace lifecycle

- Account login/disable concurrency commit `455c8c3` passed GitHub Actions backend, frontend and disposable PostgreSQL: https://github.com/oldman-552/cicc/actions/runs/41435065254.
- Added trusted CLI workspace disable/enable, each transactionally revoking sessions and writing mutable audit. PostgreSQL logins and account configuration take a workspace row lock before the user lock; `FOR NO KEY UPDATE` remains compatible with foreign-key key-share locks. This serializes logins within a workspace and is not load-tested. Direct database edits bypass the lifecycle; in-flight requests can finish, and SQLite concurrency remains uncertified.
- Synthetic SQLite tests cover workspace-scoped revocation, reactivation and rollback. A PostgreSQL login/lifecycle race test is pending CI. Local backend: 89 passed, 10 PostgreSQL skipped; schema check and pip check passed; frontend remains 12 passed, build and npm audit passed previously.

- Workspace lifecycle commit `d087fce` passed backend, frontend and disposable PostgreSQL GitHub Actions, including the selected login/deactivation race test: https://github.com/oldman-552/cicc/actions/runs/41435452428. This does not certify all concurrency cases or production isolation.

### PostgreSQL scoped-link concurrency test

- Added a disposable PostgreSQL test for both orderings of scoped investigation–asset link creation and asset deletion; it checks that a committed link prevents deletion and a committed deletion prevents link creation. PostgreSQL CI is required to determine the outcome; this is not comprehensive tenant isolation testing.
- PostgreSQL-only tests are skipped locally (11 total); last complete local run had 89 backend passes.

- Scoped-link concurrency commit `a2ad650` passed GitHub Actions backend, frontend and disposable PostgreSQL: https://github.com/oldman-552/cicc/actions/runs/41435722572. Both tested orderings prevented a dangling investigation–asset link; this is not comprehensive isolation assurance.
