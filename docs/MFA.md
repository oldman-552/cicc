# Optional local TOTP (development only)

CICC supports optional six-digit, 30-second TOTP for locally managed accounts. By default it is **not enforced**: existing and new accounts without enrollment still authenticate with a password alone. A deployment-wide opt-in enforcement flag is available as described below. Enrollment is performed by a trusted server operator, not through a self-service UI. This does not constitute enterprise identity, SSO, phishing-resistant authentication or production security certification. The preview's demo mode bypasses all authentication, including TOTP; never use it with sensitive information.

## Key management

`CICC_MFA_KEY` must be a stable, randomly generated, URL-safe base64 encoding of exactly 32 bytes, made available to both the API and the trusted CLI. Never paste it into chat, commit it or place it in command history. Generate and store it using an approved local secrets process; for disposable local development only, an example is:

```sh
export CICC_MFA_KEY="$(python -c 'import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')"
```

The example generates a **new** key each time. Do not regenerate it on restart once accounts are enrolled. A trusted operator must securely preserve and provision the same key to every relevant API instance and CLI process. The database stores TOTP seeds encrypted with AES-256-GCM, random nonces and user-bound associated data. Other application data is not encrypted by this feature. Environment variables may be visible to system/container administrators; no managed secret vault, online rotation or secure backup is provided. An offline rotation command is available as described below. A missing, invalid or wrong key returns an authentication-unavailable error for enrolled accounts and **does not bypass MFA**. Loss of the key makes enrolled accounts unable to sign in until a trusted local recovery reset; safe recovery and rotation procedures are not certified.

## Optional enforcement

To require enrolled TOTP for every authenticated local account, first enroll each required account, then set `CICC_REQUIRE_MFA=1` in the API environment and restart it. A login without enrollment is rejected, and password-only sessions are rejected while this policy is active. The authenticated platform-status page shows the account enrollment and deployment policy states. Sessions record whether TOTP was verified; existing sessions are conservatively marked unverified by the migration. Regardless of the policy, sessions for an enrolled account must have passed TOTP. This setting defaults to `0`; invalid values fail server startup. Do not enable it until the stable key and a trusted recovery process are in place, or administrators can be locked out. `CICC_DEMO_MODE=1` still bypasses authentication even if enforcement is enabled. This is a basic deployment-wide switch, not granular or phishing-resistant enterprise MFA policy.

## Enroll and recover

Apply migrations first, create the account, securely provision the key, then from a private local terminal run:

```sh
python -m backend.app.mfa enroll USER --workspace SLUG
```

The command displays an `otpauth://` URI containing the **secret** once and prompts for a current code to confirm. It does not generate an external QR code or contact a third party. Protect terminal output/scrollback and logs; never send the URI to anyone else. Successful enrollment revokes the account's existing sessions. The confirmation code is consumed, so wait for the next code before signing in. Login accepts an optional code field; enrolled accounts require a valid password and an unused TOTP. A ±30-second window is allowed, and an atomic counter rejects replay. A correctly synchronized server clock is required. Existing database login throttling also applies to incorrect TOTP, but is not distributed or comprehensive and can be abused for account lockout.

A trusted local administrator may recover a lost authenticator by removing enrollment and revoking sessions:

```sh
python -m backend.app.mfa reset USER --workspace SLUG --confirm-reset
```

Re-enroll promptly. This reset is intentionally powerful: trusted server/database access can bypass MFA. It generates a mutable `local-cli` audit event without independently identifying the operator. Enrollment and reset revoke sessions transactionally; requests already in flight may still finish. SQLite does not provide PostgreSQL-style row locks and concurrent enrollment/login is not certified. PostgreSQL uses row locks for account changes and login, plus an atomic replay counter; concurrency must be tested in the target deployment. No recovery codes, WebAuthn, granular enterprise MFA policy, verified operator identity, online key rotation, distributed lockout or security audit are included. Downgrading either MFA/session-assurance migration is refused while any enrollment remains, to avoid silently disabling MFA.

## Offline key rotation (development only)

The trusted CLI can rotate **all** enrolled accounts across all workspaces in one database transaction, up to 1,000 accounts. Stop every API instance and all account/MFA writers first, and independently verify that no process is accessing the database; the confirmation flag is an operator acknowledgment, **not an automated check**. Securely back up the database and both keys using procedures appropriate to the environment. Supply the existing key as `CICC_MFA_KEY` and a distinct new 32-byte URL-safe base64 key as `CICC_MFA_NEW_KEY` through a protected local environment. Do not put keys in command arguments, logs, Git, chat or terminal history. Then run:

```sh
python -m backend.app.mfa rotate-key --confirm-offline-rotation
```

The command validates all encrypted seeds before changing any, re-encrypts them under the new key, revokes affected sessions and records mutable per-workspace audit counts. It prints no keys or seeds. Once the transaction is confirmed successful, configure **every** API and MFA CLI process with the new `CICC_MFA_KEY`, remove `CICC_MFA_NEW_KEY` from the environment and restart services. Retain keys and backups according to your security and recovery policy. If a connection or process fails during commit, the outcome may be uncertain: keep services stopped and inspect the database and keys with trusted tools before retrying or restoring; do not assume success or rollback. The command does not orchestrate downtime, distribute keys, protect environment variables from system administrators or provide a tested production recovery procedure. PostgreSQL verification of the rotation revision passed in disposable CI; this is not a production recovery or downtime drill.
