"""SQLite storage (WAL mode). The worker is the single ingestion writer;
the API writes only analyst verdicts."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_uid    TEXT PRIMARY KEY,
    cw_event_id  TEXT,
    sensor       TEXT NOT NULL,
    session      TEXT,
    eventid      TEXT NOT NULL,
    ts           REAL NOT NULL,
    ts_iso       TEXT NOT NULL,
    src_ip       TEXT,
    data         TEXT NOT NULL,
    ingested_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_session ON events(sensor, session, ts);

CREATE TABLE IF NOT EXISTS sessions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor             TEXT NOT NULL,
    session            TEXT NOT NULL,
    src_ip             TEXT,
    src_port           INTEGER,
    start_ts           REAL,
    end_ts             REAL,
    last_event_ts      REAL,
    status             TEXT NOT NULL DEFAULT 'open',
    closed_reason      TEXT,
    duration           REAL,
    client_version     TEXT,
    event_count        INTEGER DEFAULT 0,
    login_failed       INTEGER DEFAULT 0,
    login_success      INTEGER DEFAULT 0,
    username           TEXT,
    usernames          TEXT DEFAULT '[]',
    command_count      INTEGER DEFAULT 0,
    commands_failed    INTEGER DEFAULT 0,
    first_command_ts   REAL,
    categories         TEXT DEFAULT '[]',
    download_count     INTEGER DEFAULT 0,
    mean_gap           REAL DEFAULT 0,
    outcome            TEXT,
    is_demo            INTEGER DEFAULT 0,
    max_severity       INTEGER DEFAULT 0,
    alert_count        INTEGER DEFAULT 0,
    anomaly_score      REAL,
    anomaly_pct        REAL,
    model_version      TEXT,
    features           TEXT,
    explanation        TEXT,
    verdict            TEXT,
    verdict_note       TEXT,
    verdict_at         REAL,
    UNIQUE(sensor, session)
);
CREATE INDEX IF NOT EXISTS ix_sessions_start ON sessions(start_ts);
CREATE INDEX IF NOT EXISTS ix_sessions_src ON sessions(src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key        TEXT UNIQUE NOT NULL,
    rule_id          TEXT NOT NULL,
    title            TEXT NOT NULL,
    severity         TEXT NOT NULL,
    severity_rank    INTEGER NOT NULL,
    sensor           TEXT,
    session_id       INTEGER,
    related_sessions TEXT DEFAULT '[]',
    src_ip           TEXT,
    reason           TEXT NOT NULL,
    evidence         TEXT NOT NULL,
    first_ts         REAL,
    last_ts          REAL,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL,
    status           TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status, severity_rank);

CREATE TABLE IF NOT EXISTS sensors (
    sensor             TEXT PRIMARY KEY,
    first_seen         REAL,
    last_heartbeat_ts  REAL,
    last_event_ts      REAL,
    shipped_total      INTEGER,
    cowrie_log_age_s   REAL,
    collector_version  TEXT
);

CREATE TABLE IF NOT EXISTS alert_sessions (
    alert_id    INTEGER NOT NULL,
    session_id  INTEGER NOT NULL,
    PRIMARY KEY (alert_id, session_id)
);
CREATE INDEX IF NOT EXISTS ix_alert_sessions_session ON alert_sessions(session_id);

-- Imported historical logs. Their events/sessions/alerts carry dataset_id;
-- live sensor data has dataset_id NULL.
CREATE TABLE IF NOT EXISTS datasets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    filename       TEXT NOT NULL,
    created_at     REAL NOT NULL,
    status         TEXT NOT NULL,          -- importing | ready | failed
    stage          TEXT,
    progress       REAL DEFAULT 0,
    total_rows     INTEGER DEFAULT 0,
    accepted_rows  INTEGER DEFAULT 0,
    rejected_rows  INTEGER DEFAULT 0,
    duplicate_rows INTEGER DEFAULT 0,
    events         INTEGER DEFAULT 0,
    sessions       INTEGER DEFAULT 0,
    alerts         INTEGER DEFAULT 0,
    first_ts       REAL,
    last_ts        REAL,
    report         TEXT,                   -- validation report (JSON)
    error          TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL COLLATE NOCASE,
    pw_hash     TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('analyst', 'admin')),
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  REAL NOT NULL,
    last_login  REAL
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    last_seen   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_user ON auth_sessions(user_id);

CREATE TABLE IF NOT EXISTS checkpoints (
    name   TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS models (
    version        TEXT PRIMARY KEY,
    created_at     REAL NOT NULL,
    n_train        INTEGER NOT NULL,
    train_from     REAL,
    train_to       REAL,
    feature_version TEXT NOT NULL,
    path           TEXT NOT NULL,
    stats          TEXT NOT NULL,
    active         INTEGER NOT NULL DEFAULT 0
);
"""

_local = threading.local()


def connect() -> sqlite3.Connection:
    os.makedirs(settings.data_dir, exist_ok=True)
    conn = sqlite3.connect(settings.db_path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = connect()
        _local.conn = conn
    return conn


def _columns(conn, table: str) -> set[str]:
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}


def _migrate(conn) -> None:
    """Upgrade databases created before Dataset Import existed."""
    for table, col, ddl in (
        ("events", "dataset_id", "INTEGER"),
        ("sessions", "dataset_id", "INTEGER"),
        ("sessions", "protocol", "TEXT"),
        ("alerts", "dataset_id", "INTEGER"),
        ("models", "scope", "TEXT NOT NULL DEFAULT 'live'"),
        ("sessions", "verdict_by", "TEXT"),
    ):
        if col not in _columns(conn, table):
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
    for col, ddl in (("stats", "TEXT"), ("pid", "INTEGER")):
        if col not in _columns(conn, "datasets"):
            conn.execute(f"ALTER TABLE datasets ADD COLUMN {col} {ddl}")
    # Indexes matched to the real queries. Fewer indexes on events = faster imports.
    conn.executescript("""
        DROP INDEX IF EXISTS ix_events_src;
        DROP INDEX IF EXISTS ix_events_type_ts;
        DROP INDEX IF EXISTS ix_events_dataset;
        DROP INDEX IF EXISTS ix_events_scope_src;
        CREATE INDEX IF NOT EXISTS ix_events_scope_type ON events(dataset_id, eventid, ts);
        CREATE INDEX IF NOT EXISTS ix_events_scope_src2 ON events(dataset_id, eventid, src_ip, ts);
        CREATE INDEX IF NOT EXISTS ix_sessions_dataset ON sessions(dataset_id, start_ts);
        CREATE INDEX IF NOT EXISTS ix_sessions_anomaly ON sessions(dataset_id, anomaly_pct);
        CREATE INDEX IF NOT EXISTS ix_sessions_severity ON sessions(dataset_id, max_severity, alert_count, start_ts);
        CREATE INDEX IF NOT EXISTS ix_alerts_dataset ON alerts(dataset_id, status, severity_rank);
        CREATE INDEX IF NOT EXISTS ix_alerts_src ON alerts(src_ip, rule_id, dataset_id);
    """)
    # rule titles renamed for precision (ids unchanged)
    for rule_id, title in (("AUTH_BRUTE_SOURCE", "Repeated login failures across connections"),
                           ("DROPPER_CHAIN", "Download followed by execution attempt"),
                           ("PAYLOAD_DOWNLOAD", "Download attempt in the emulated shell")):
        conn.execute("UPDATE alerts SET title=? WHERE rule_id=? AND title<>?", (title, rule_id, title))
    # backfill the alert->session map from older rows
    if conn.execute("SELECT COUNT(*) c FROM alert_sessions").fetchone()["c"] == 0:
        conn.execute("""INSERT OR IGNORE INTO alert_sessions(alert_id, session_id)
                        SELECT a.id, j.value FROM alerts a, json_each(a.related_sessions) j""")
        conn.execute("""INSERT OR IGNORE INTO alert_sessions(alert_id, session_id)
                        SELECT id, session_id FROM alerts WHERE session_id IS NOT NULL""")


def init() -> None:
    conn = get_conn()
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.commit()


def scope_sql(scope: str | None, col: str = "dataset_id") -> tuple[str, list]:
    """'live' (default) | 'ds:<id>' | 'all' -> SQL condition on dataset_id."""
    scope = (scope or "live").strip()
    if scope == "all":
        return "1=1", []
    if scope.startswith("ds:"):
        try:
            return f"{col} = ?", [int(scope[3:])]
        except ValueError:
            pass
        raise ValueError("scope must be 'live', 'all' or 'ds:<dataset id>'")
    if scope == "live":
        return f"{col} IS NULL", []
    raise ValueError("scope must be 'live', 'all' or 'ds:<dataset id>'")


@contextmanager
def tx():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def get_checkpoint(name: str, default=None):
    row = get_conn().execute("SELECT value FROM checkpoints WHERE name=?", (name,)).fetchone()
    return json.loads(row["value"]) if row else default


def set_checkpoint(conn: sqlite3.Connection, name: str, value) -> None:
    conn.execute(
        "INSERT INTO checkpoints(name, value) VALUES(?, ?) "
        "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
        (name, json.dumps(value)),
    )


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for key in ("usernames", "categories", "features", "explanation", "evidence",
                "related_sessions", "data", "stats"):
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except json.JSONDecodeError:
                pass
    return d
