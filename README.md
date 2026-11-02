# CICC — Cyber Intelligence Command Center

CICC is an **early development foundation**, not the completed enterprise platform. This repository starts from an empty checkout and provides an integrated initial slice: a three-language command center; public GitHub advisory, CISA KEV and limited CVE Program and MITRE ATT&CK collection, plus a mocked-only FIRST EPSS adapter; investigations, source snapshots, notes and local activity timelines; manually attested asset inventory and SBOM associations; a limited 3D reference view with a 2D list; and offline SBOM metadata correlation. See [PROJECT_STATUS.md](PROJECT_STATUS.md), [IMPLEMENTATION_TRACKER.md](IMPLEMENTATION_TRACKER.md), and [BLOCKERS.md](BLOCKERS.md) for verified scope and outstanding work.

> **Security warning:** This is not production-ready. Local accounts, coarse roles and experimental application-level workspace scoping exist, but local TOTP enforcement is off by default and there is no production tenant isolation, fine-grained permissions, encrypted evidence storage, hardened audit, or production security review. The optional demo mode disables authentication entirely. Run only in a trusted, isolated development environment with non-sensitive data. Do not expose it publicly.

## Local setup

Requirements: Python 3.11+, Node 22+, npm 10.5+. SQLite is the default for isolated development; PostgreSQL can be configured with `DATABASE_URL`.

```sh
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
.venv/bin/alembic -c backend/alembic.ini upgrade head
# Create a local admin interactively in the default workspace; no credentials are seeded.
.venv/bin/python -m backend.app.accounts admin --role admin
.venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```sh
cd frontend
npm ci
npm run dev
```

Open the Vite URL. Its server proxies `/api` to the backend; browser code does not call localhost directly. API docs are at `http://127.0.0.1:8000/docs`. Roles are `admin`, `analyst` and `viewer`; creating or resetting an account uses the interactive command and revokes its sessions. Disable an account and revoke its sessions with `python -m backend.app.accounts USER --workspace SLUG --disable`. Signed-in users can revoke their other sessions from the platform-status page; requests already in flight may still finish. Local CLI account and workspace changes produce mutable audit records labeled `local-cli`, which does not identify or authenticate the operating-system operator. Authentication is required by default. Session cookies are Secure and SameSite=Strict; use HTTPS or a browser's localhost secure-context exception. `CICC_INSECURE_COOKIES=1` is for isolated HTTP development only.

Local TOTP can be enrolled by a trusted server operator; it requires a stable externally managed key. Accounts without enrollment remain password-only unless the optional deployment-wide enforcement switch is enabled. See [docs/MFA.md](docs/MFA.md) before enabling it.

For a **disposable, non-sensitive preview only**, `CICC_DEMO_MODE=1` grants unauthenticated full access. The Arena live preview runs in this mode and is explicitly labelled. Never use it with sensitive data.

## Data and source provenance

Outside demo, shared-source refresh is disabled until trusted admin usernames are explicitly configured in `CICC_GLOBAL_SOURCE_OPERATORS`; see [workspace security](docs/WORKSPACES.md). Manual refresh collects 30 recent public GitHub advisories and the full CISA KEV catalog from the official `cisagov/kev-data` GitHub mirror. The CVE Program adapter retrieves up to 10 CVE records referenced by cached GitHub advisories from the official `CVEProject/cvelistV5` repository; it is not a comprehensive CVE feed and requires the GitHub cache first. The MITRE ATT&CK adapter retrieves a deterministic 10-file sample from the official MITRE CTI STIX repository, not the full catalog. A new FIRST EPSS adapter can enrich up to 30 cached advisory CVEs, but was only tested with mocked responses because FIRST is outside this environment’s permitted outbound hosts; see [docs/EPSS.md](docs/EPSS.md). Cached records show collection time, source and verification state. A failure retains the prior cache. KEV membership is source-reported, not proof an asset is affected; absence is not proof of safety. The globe is explicitly an illustration, not live geography. The 3D reference view uses explicit investigation links to evidence, user-attested assets and ATT&CK references.

SBOM import reads top-level CycloneDX/SPDX JSON metadata (up to 1 MiB and 500 components) and compares supported package identities to the advisories cached at import time. A conservative subset of stable npm and PyPI versions and source ranges is compared; unsupported or ambiguous cases remain unknown. A range match is not a confirmed vulnerability, and no matches or an out-of-range result do not establish safety. See [docs/SBOM.md](docs/SBOM.md) for exact limits. Supplied files are never executed or fetched.

## ATT&CK and investigation activity

ATT&CK technique links are source-reported research references, not evidence of an incident or attribution. The local investigation timeline is not tamper-resistant and does not backfill older history. New advisory snapshots have a same-database consistency checksum, not proof of authenticity or tamper resistance. See [docs/ATTACK.md](docs/ATTACK.md) and [docs/TIMELINE.md](docs/TIMELINE.md) and [docs/EVIDENCE.md](docs/EVIDENCE.md).

The administrator audit view supports paging and exact-action filtering. It is mutable and omits unscoped login failures; public source updates are shared. See [docs/AUDIT.md](docs/AUDIT.md). The UI uses system fonts rather than fetching third-party fonts at runtime.

## Manually scoped assets

Analysts can register asset metadata only after attesting authorization, then link active assets to investigations and imported SBOMs. These are user claims, **not verified ownership, deployment, exposure or vulnerability findings**. No scanning or network access is performed by these features. Asset details are visible to roles in the same development workspace and are not encrypted; never put sensitive inventory in demo mode. See [docs/ASSETS.md](docs/ASSETS.md).

## Development workspaces

Accounts can be assigned to local workspaces with the CLI; private application records are scoped to the account workspace, while all public source caches and refreshes are shared globally. These checks are not production tenant isolation. The demo bypasses authentication and uses the default workspace. See [docs/WORKSPACES.md](docs/WORKSPACES.md) for commands, audit attribution and limitations.

## Development Docker Compose

The Compose configuration uses PostgreSQL and exposes only the Vite development server on `127.0.0.1:5173`. **Docker is unavailable in the current environment: images, network, volume permissions and recovery have not been tested.** It is not a production deployment. Copy `.env.example` to `.env` and set a URL-safe `POSTGRES_PASSWORD` locally (e.g. generate using `openssl rand -hex 32`); do not send it in chat or commit it.

```sh
docker compose up -d db
docker compose run --build --rm api python -m backend.app.accounts admin --role admin
docker compose up --build
```

`docker compose down -v` deletes database data. No recovery drill has been performed. See [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Tests

```sh
.venv/bin/python -m pytest -q backend/tests
.venv/bin/alembic -c backend/alembic.ini check
cd frontend && npm test && npm run build && npm audit --audit-level=high
```

The frontend tests use a simulated DOM; they do not establish real-browser, WebGL, accessibility or performance compliance. PostgreSQL, Docker, disaster recovery, tenant isolation and production security testing have not been verified.

Development-only, unencrypted SQLite copy/verification and recovery limitations: [docs/RECOVERY.md](docs/RECOVERY.md). This is not a production backup service.
