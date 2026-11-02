# SQLite development copy and recovery limitations

`python -m backend.app.sqlite_backup` is a trusted-local, **unencrypted** SQLite copy utility. It is not a backup service or production disaster-recovery solution and does not support PostgreSQL. Files can include accounts, sessions, inventory, audit records, intelligence and other sensitive material. Use a protected directory **outside the repository**, restrict access, and protect/encrypt and retain copies through independently managed infrastructure. The tool creates a new destination with owner-only permissions (subject to the operating system), refuses any existing destination including symlinks, uses SQLite's online backup API and checks `PRAGMA integrity_check`. It does not authenticate data, encrypt it, prove migration completeness, include external MFA keys, enforce retention, replicate backups or guarantee filesystem durability. A hard kill or power loss can leave an incomplete output or SQLite sidecars; inspect and verify in a trusted isolated environment before use. Do not process untrusted database files.

To copy a trusted SQLite database to a **new** path, or to copy a backup into another **new** path for an isolated test:

```sh
python -m backend.app.sqlite_backup copy /protected/source.db /protected/new-copy.sqlite3
python -m backend.app.sqlite_backup verify /protected/new-copy.sqlite3
```

Neither operation overwrites an existing database. A successful check tests SQLite's internal integrity only; it does not verify authenticity, schema, correctness or application recoverability. Before switching any running deployment to a restored database, independently validate application behavior, access policy, audit implications, migration state and the separately secured MFA key in isolation. **Snapshots can revive sessions already revoked after the snapshot, restore old passwords or MFA enrollment, and roll back audit and workspace changes.** The utility does not automatically invalidate sessions or reconcile later changes. Recovery into a running deployment and any destructive replacement require an authorized operator and a separately tested procedure. No actual production recovery drill has been performed.
