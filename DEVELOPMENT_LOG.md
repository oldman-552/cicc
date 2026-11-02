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

### Child parent guard and asset–SBOM race tests

- Implemented the saved checkpoint: disposable PostgreSQL race tests cover insert-versus-delete of either asset or SBOM. Pending CI because PostgreSQL is unavailable locally.
- Added migration `a63c9f170b42` and ORM guards preventing parent reassignment for six workspace-derived child tables. Preflight refuses orphaned rows and downgrade refuses removal while those tables have records; existing ownership provenance cannot be reconstructed. Applied migration to the development SQLite database.
- Synthetic SQLite tests cover direct SQL, no-op changes, rollback/downgrade refusal, migration preflight and ORM guard. Local backend 92 passed/14 PostgreSQL skipped; 12 frontend tests, build, Alembic and pip checks, npm audit passed. Three.js chunk warning remains. This is not production isolation.

### Development SQLite restore-to-new

- Child-parent guard and asset–SBOM race commit `9a2c12d` passed backend, frontend and disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41436533643. These controls are not RLS.
- Added staged SQLite restore to a new file. It checks recorded migration head and database integrity, removes every saved session transactionally, writes a mutable unscoped recovery audit entry and publishes by non-overwriting hard link. It requires explicit acknowledgment that passwords, MFA and audit history may be stale. No encryption, backup authentication, production recovery or PostgreSQL recovery is claimed.
- Synthetic tests cover all-workspace revocation, unchanged source, schema mismatch, existing target, failed sanitization and CLI acknowledgment. Local result 95 backend passed, 14 PostgreSQL skipped; 12 frontend passed, build, schema check, pip check and npm audit passed. CI pending.

### Experimental authenticated SQLite backup

- SQLite restore commit `057aca5` passed backend, frontend and disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41436843876.
- Added a trusted-local AES-256-GCM encrypted SQLite backup format with an external 32-byte key, authenticated header and non-overwriting publication. Restore authenticates before publishing and then invalidates saved sessions. Protected plaintext staging, separate MFA/backup keys, stale security state and replay risk are explicitly documented; this is neither a production backup service nor a PostgreSQL solution.
- Synthetic tests cover round-trip, session revocation, wrong key, modified header/nonce/ciphertext/tag, truncation, size limit, collisions, key lengths and acknowledgments. Local backend 105 passed/14 PostgreSQL skipped; CI pending. No independent cryptographic review or production recovery drill.

### Unknown role fail-closed

- Experimental encrypted SQLite backup commit `c655546` passed backend, frontend and disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41437204707. No cryptographic or production recovery certification.
- Fixed a privilege failure: previously an unexpected database role was treated as non-viewer for some writes. Login and session validation now reject all roles except admin, analyst and viewer. Trusted CLI repair revokes old sessions; direct SQL changes bypass account lifecycle.
- SQLite tests exercise unexpected, empty and malformed roles for both existing sessions and login; PostgreSQL equivalent is pending CI. Local backend 109 passed/15 PostgreSQL skipped; Alembic and pip checks passed. Frontend 12 tests, build and npm audit passed on the previous revision.

### Database account-role guard

- Unknown-role fail-closed commit `cfb48c4` passed backend, frontend and disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41437432959.
- Added migration `c1af7842d90b`: preflight rejects unsupported persisted roles; SQLite triggers or a PostgreSQL check constrain future roles; downgrade refuses while accounts exist. This does not stop a privileged database actor from granting another valid role. Applied locally to development SQLite.
- SQLite migration tests cover unsupported legacy roles, direct SQL insert/update, valid roles and guarded downgrade. Backend 111 passed/15 PostgreSQL skipped; 12 frontend tests, build, Alembic and pip checks and npm audit passed. PostgreSQL migration check pending CI.

### Security-state database revocation

- Account role-guard commit `cb2d4d7` passed backend, frontend and disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41437758338.
- Added migration `ea2dd04051c8`: transactional database triggers revoke affected sessions for ordinary account identity/role/password/active, workspace active, and MFA enrollment/secret changes; unchanged values and MFA counter updates do not revoke. Session and MFA user references are immutable on update. This does not audit direct SQL, repair historical state, stop privileged actors or certify SQLite concurrency.
- Migrated SQLite tests cover scoped revocation, rollback, no-op and replay-counter updates, MFA lifecycle, parent immutability and guarded downgrade. Local backend 120 passed/16 PostgreSQL skipped; Alembic and pip checks passed. PostgreSQL trigger verification pending CI.

### Direct workspace-change/login race

- Security-state revocation migration commit `1c047d5` passed backend, frontend and disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41438149536. Privileged DB actions and unaudited direct changes remain outside comprehensive isolation assurance.
- Added PostgreSQL-only coverage for login against direct SQL workspace deactivation in both transaction orderings, including reactivation without session revival; CI is required to validate it. Local baseline 120 backend passed, 17 PostgreSQL skipped.

### Asset mutation/link concurrency fix

- Direct workspace/login race commit `52a917e` passed backend, frontend and disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41438417897.
- Fixed an application-level time-of-check/time-of-use gap: PostgreSQL asset identity/status updates and both asset link operations now acquire the asset row lock before checking status or identity. SQLite has no equivalent row locks; direct privileged SQL remains outside this application guarantee.
- Added PostgreSQL tests for both orderings of identity change and retirement against investigation and SBOM linking; these tests require CI. Local backend 120 passed/21 PostgreSQL skipped; frontend 12 passed, build, Alembic/pip checks, npm audit passed.

### Explicit global source operators

- Asset lock/race commit `5ae07e0` passed backend, frontend and disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41438744913. SQLite concurrency remains uncertified.
- Closed a cross-workspace control gap: authenticated global cache refresh is now disabled by default and requires an admin username explicitly listed in `CICC_GLOBAL_SOURCE_OPERATORS`, plus CSRF. Demo still bypasses authentication; public caches remain globally shared and the configuration is not enterprise operator governance. UI capability and disabled reason are localized EN/AR/FA.
- Local synthetic tests cover two workspaces, admin/analyst denial, explicit operator, CSRF, fail-closed malformed configuration and 3-language UI. PostgreSQL test awaits CI. Local backend 122 passed/22 PostgreSQL skipped; 13 frontend passed, build, Alembic/pip checks and npm audit passed.

### Source refresh publication ordering

- Global source operator policy commit `c9a441e` passed backend, frontend and disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41439176996. Caches remain globally shared; this is not production tenant isolation.
- Fixed stale source refresh publication: source-row creation is conflict-safe, PostgreSQL publication locks the source row, and older attempts return 409 without overriding a later completed result or error. Ordering uses application wall clocks; distributed clock skew and SQLite concurrency remain limitations.
- Synthetic SQLite tests cover older success/failure against newer success/failure. Equivalent PostgreSQL races await CI. Local backend 125 passed/25 PostgreSQL skipped; frontend 13 passed, build, Alembic/pip checks and npm audit passed.

### Database-issued source attempt ordering

- Source refresh race commit `70fe13e` passed backend, frontend and disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41439546375.
- Replaced wall-clock ordering with per-source monotonic database-issued tickets reserved in a short transaction before collection. Later completed tickets supersede older attempts even when application clocks regress. Displayed timestamps still use application clocks, and crashes can leave gaps. Migration `2ecb93a547b1` preserves existing source rows with zero counters and refuses downgrade while source rows exist; SQLite version must support UPDATE RETURNING. Applied to the local development database.
- SQLite synthetic tests cover clock regression, migration preservation and downgrade refusal; PostgreSQL equivalent awaits CI. Local backend 127 passed/26 PostgreSQL skipped; 13 frontend tests, build, Alembic/pip checks and npm audit passed.

### Expanded cross-workspace API checks

- Database-issued source sequence commit `4d3878c` passed backend, frontend and disposable PostgreSQL CI, including clock regression: https://github.com/oldman-552/cicc/actions/runs/41439978311. Displayed timestamps remain clock-dependent.
- Expanded cross-workspace denial checks to asset metadata and SBOM associations and investigation evidence, technique, note and asset links. SQLite API checks passed; PostgreSQL variants await CI. No RLS or comprehensive isolation claim.

### Concurrent login throttling

- Expanded cross-workspace denial tests in commit `8892bfb` passed backend, frontend and disposable PostgreSQL CI: https://github.com/oldman-552/cicc/actions/runs/41440199035. These do not establish production isolation.
- Login throttle checks now acquire ordered PostgreSQL transaction advisory locks by account/client before querying or verifying passwords, serializing concurrent requests across updated workers sharing one database; SQLite uses a coarse write lock and returns 503 if acquisition fails. Time windows use application clocks; observed IP depends on trusted proxy setup. Mixed versions, independent databases, lockout abuse, resource exhaustion and SQLite contention remain limitations. This is not edge DDoS protection.
- SQLite concurrent tests passed (10 requests on one account, 31 from one client), including fail-closed lock error. PostgreSQL concurrent validation is pending CI. Local backend 129 passed/27 PostgreSQL skipped; frontend 13 passed, build, Alembic/pip checks and npm audit passed.
