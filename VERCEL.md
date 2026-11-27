# Deploying VoidSentinel on Vercel

The root `vercel.json` deploys the Vite frontend and FastAPI backend together.
Import this repository with **Root Directory** set to the repository root. Keep
the service configuration in `vercel.json`; no separate backend host is needed.

## Persistent database

Connect the existing Turso database to the Vercel project, including Preview if
you want authenticated preview testing. The backend expects these variables:

| Variable | Value |
| --- | --- |
| `TURSO_DATABASE_URL` | The database's `libsql://...` URL |
| `TURSO_AUTH_TOKEN` | Its write token, stored as a Vercel Secret |
| `VS_ADMIN_USERNAME` | Initial administrator username; defaults to `admin` |
| `VS_ADMIN_PASSWORD` | Initial administrator password, stored as a Secret |
| `VS_ANALYST_PASSWORD` | Initial analyst password, stored as a Secret |

Redeploy after changing environment variables. An existing database keeps its
users, passwords and imported data. Neon is PostgreSQL and cannot replace this
SQLite/libSQL database by changing the connection URL alone.

On Vercel the app refuses to start without a persistent database rather than
silently using an instance's temporary SQLite file. `/tmp/voidsentinel` is used
only for scratch analysis and cached model files.

## Upload and analysis

The browser uploads 2 MiB chunks, each below Vercel's default 4.5 MB request
limit. The shared database stores chunk hashes, upload status, validation
reports, staged data and analysis publication checkpoints. Retrying a chunk
with the same bytes is safe; missing or changed chunks are rejected.

Each **Process** request claims a database lease and finishes its work before
returning. Validation and analysis each use a fresh temporary directory. Analysis
runs the existing detection and anomaly pipeline against an isolated SQLite
database, then publishes the results to Turso in short transactions. Session and
alert IDs are reserved before publication, preserving links to evidence and
avoiding collisions with other imports or live data. The trained model is also
stored in Turso, so another Vercel instance can load it.

The import page advances the job using sequential requests. Keep it open while
processing. A reload resumes the current analysis; **Resume analysis** in the
dataset list resumes it from another tab. If Vercel terminates a request, its
lease expires after six minutes and another request can retry. Completed
publication batches are retained. Validation and CPU analysis restart their
current phase if interrupted. No child process or post-response background work
is used for this protocol.

The backend function has a 300-second request duration. Each validation and CPU
analysis phase must fit that limit and the function's memory and temporary disk
limits. Publication is split across requests with a 15-second work budget.
The 1 GiB application upload ceiling is not a guarantee that any 1 GiB archive
can be analyzed within a Vercel function's resources; use the CLI importer for
files exceeding those compute limits.

Raw uploads and intermediate results are removed after publication. Abandoned
uploads and previews expire after 24 hours and are cleaned on the next upload.
Live sensor collection still requires the existing sensor/worker setup; Vercel
does not run a continuous CloudWatch polling worker.

## Verification

```powershell
cd backend
python -m pytest -q
cd ../frontend
npm ci
npm run build
cd ..
python tools/verify_import.py C:/path/to/archive.zip
python tools/verify_import.py C:/path/to/archive.zip --url https://your-app.vercel.app --username admin
```

The remote verifier prompts for the password, or reads `VS_VERIFY_PASSWORD`.
It uploads, validates, imports, and checks the overview, sessions, alert evidence
and trained model. Remote verification creates a dataset in the target app.

## Recovering an existing admin account

If the database's admin password differs from the expected one, set
`VS_ADMIN_USERNAME`, `VS_ADMIN_PASSWORD`, and a new unique
`VS_ADMIN_PASSWORD_RESET_VERSION` in Vercel, then redeploy. The reset version is
recorded in the database and applied only once, revoking the account's existing
sessions. Later password changes in Access survive cold starts. Remove the reset
version after recovery. Changing `VS_ADMIN_PASSWORD` by itself only configures
initial account creation; it does not overwrite an existing account.

Vercel limits reference: [Function limitations](https://vercel.com/docs/functions/limitations).
