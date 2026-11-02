# Development workspace scoping

This is an application-level development feature, **not production tenant isolation**. It must only be used with non-sensitive test data in a trusted environment. Requests using local accounts scope investigations, their evidence/notes/events/links, manually entered assets, SBOMs and authenticated audit events to the account's active workspace. Roles are shared across each workspace, not per-object permissions. The interface displays the workspace name. Demo mode bypasses authentication and always uses workspace `default` (ID 1).

Public advisories, CISA KEV, CVE records, ATT&CK techniques and source status are global: every workspace sees the same cache, and an admin in **any** workspace can refresh it for everyone. Global source changes are not independently isolated. Login failures for an unknown, inactive or unavailable account are unscoped and the workspace audit endpoint does not expose them; failures for a known active account are attributed to that account’s workspace. Admins cannot use it to investigate all authentication failures. Audit is mutable and not suitable for compliance or forensics.

## Local administration

With the virtual environment active and migrations applied:

```sh
python -m backend.app.workspaces research 'Research development'
python -m backend.app.accounts alice --role admin --workspace research
python -m backend.app.accounts bob --role analyst --workspace research
```

Workspace creation and account management require trusted local server/database access. Passwords are prompted interactively, never passed on the command line. Omitting `--workspace` chooses `default`. Workspace slugs are lowercase letters, digits and single internal hyphens, 1–40 characters. Existing accounts cannot be moved with this CLI; updating an account revokes its sessions. Deactivating a workspace in the database invalidates its sessions. There is no management UI, self-service enrollment, account migration or audited administrative approval flow.

Migration `b8936d1c2327` places existing records, including legacy audit entries, in `default`, because their historical workspace is unknown. This is a migration convention, not evidence of their origin. The downgrade is refused if additional workspaces or scoped records remain. Back up data and review migrations before use; no restore has been tested.

## Security limits

The service checks workspace ownership in the implemented endpoints and checks both ends of manual links. An ORM hook requires explicit workspace IDs for new protected root objects and rejects reassignment, but bulk SQL, direct database access and some relationship invariants are not protected by equivalent database constraints. There is no row-level security, composite workspace foreign-key enforcement across all related records, hardened administrative boundary, comprehensive concurrency testing or independent penetration test. PostgreSQL and cross-tenant isolation in a real deployment have not been verified. Do not market these checks as enterprise isolation. A database administrator or application bug can bypass them.
