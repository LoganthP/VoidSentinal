"""Durable, request-driven imports for serverless and local deployments.

The shared database holds upload chunks, leases and publication checkpoints.
CPU-heavy analysis uses the existing importer in an isolated SQLite database;
its results are then published in bounded, atomic batches. No work is scheduled
after an HTTP response and no later request depends on the same filesystem.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
import uuid
import zipfile
import zlib
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from . import auth, db, importer
from .config import settings

CHUNK_BYTES = 2 * 1024 * 1024
LEASE_SECONDS = 360
TABLES = ("events", "sessions", "alerts", "alert_sessions", "models")
router = APIRouter(prefix="/api/datasets", dependencies=[Depends(auth.require_admin)])
log = logging.getLogger("vs.serverless_import")


def init_schema(conn, commit=True):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS import_jobs (
            token TEXT PRIMARY KEY, filename TEXT NOT NULL, size INTEGER NOT NULL,
            chunks INTEGER NOT NULL, state TEXT NOT NULL, created_at REAL NOT NULL,
            updated_at REAL NOT NULL, mapping TEXT, report TEXT, error TEXT,
            dataset_id INTEGER UNIQUE, lease TEXT, lease_until REAL DEFAULT 0,
            cursor INTEGER DEFAULT 0, batch_count INTEGER DEFAULT 0, result TEXT
        );
        CREATE TABLE IF NOT EXISTS import_parts (
            token TEXT NOT NULL, kind TEXT NOT NULL, part INTEGER NOT NULL,
            digest TEXT NOT NULL, data BLOB NOT NULL,
            PRIMARY KEY(token, kind, part)
        );
        CREATE TABLE IF NOT EXISTS model_files (
            version TEXT PRIMARY KEY, data BLOB NOT NULL
        );
    """)
    if commit:
        conn.commit()


def _job(token):
    row = db.get_conn().execute("SELECT * FROM import_jobs WHERE token=?", (token,)).fetchone()
    if row is None:
        raise HTTPException(404, "Upload not found or expired. Upload the file again.")
    return dict(row)


def _save_parts(conn, token, kind, parts):
    if not parts:
        return
    values = [(token, kind, n, hashlib.sha256(data).hexdigest(), data) for n, data in parts]
    sql = "INSERT OR REPLACE INTO import_parts(token,kind,part,digest,data) VALUES "
    conn.execute(sql + ",".join("(?,?,?,?,?)" for _ in values), [v for row in values for v in row])


def _restore(conn, token, kind, path):
    with open(path, "wb") as fh:
        # Fetch one part at a time: remote cursors may buffer their full result.
        count = conn.execute("SELECT COUNT(*) FROM import_parts WHERE token=? AND kind=?", (token, kind)).fetchone()[0]
        for i in range(count):
            row = conn.execute("SELECT data,digest FROM import_parts WHERE token=? AND kind=? AND part=?",
                               (token, kind, i)).fetchone()
            if row is None:
                raise ValueError("Upload has missing chunks; upload the file again.")
            data = bytes(row["data"])
            if hashlib.sha256(data).hexdigest() != row["digest"]:
                raise ValueError("Upload integrity check failed; upload the file again.")
            fh.write(data)


def _store_file(conn, token, kind, path):
    with open(path, "rb") as fh:
        n = 0
        while data := fh.read(CHUNK_BYTES):
            _save_parts(conn, token, kind, [(n, data)])
            conn.commit()
            n += 1


class UploadIn(BaseModel):
    filename: str = Field(min_length=1, max_length=200)
    size: int = Field(gt=0)


@router.post("/uploads")
def begin(body: UploadIn):
    if body.size > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(413, f"File exceeds the {settings.max_upload_mb} MB upload limit.")
    token = uuid.uuid4().hex
    filename = body.filename.replace("\\", "/").rsplit("/", 1)[-1][:120]
    filename = filename if filename and not filename.startswith(".") else "upload.json"
    chunks = (body.size + CHUNK_BYTES - 1) // CHUNK_BYTES
    now = time.time()
    conn = db.get_conn()
    # Abandoned previews and partial uploads expire; active imports remain resumable.
    cutoff = now - 24 * 3600
    conn.execute("DELETE FROM import_parts WHERE token IN (SELECT token FROM import_jobs "
                 "WHERE dataset_id IS NULL AND updated_at<? AND state IN ('uploading','ready','failed'))", (cutoff,))
    conn.execute("UPDATE import_jobs SET state='failed',error='Upload expired. Upload the file again.' "
                 "WHERE dataset_id IS NULL AND updated_at<? AND state IN ('uploading','ready')", (cutoff,))
    conn.execute("INSERT INTO import_jobs(token,filename,size,chunks,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                 (token, filename, body.size, chunks, "uploading", now, now))
    conn.commit()
    return {"token": token, "chunk_bytes": CHUNK_BYTES, "chunks": chunks}


@router.put("/uploads/{token}/chunks/{part}")
async def put_chunk(token: str, part: int, request: Request):
    # Enforce the bound while reading, even for requests without Content-Length.
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > CHUNK_BYTES:
            raise HTTPException(413, "Upload chunk is too large.")
    return await run_in_threadpool(_put_chunk, token, part, bytes(data))


def _put_chunk(token, part, data):
    job = _job(token)
    if job["state"] != "uploading":
        raise HTTPException(409, "Upload is already sealed.")
    if part < 0 or part >= job["chunks"]:
        raise HTTPException(400, "Invalid upload chunk number.")
    expected = min(CHUNK_BYTES, job["size"] - part * CHUNK_BYTES)
    if len(data) != expected:
        raise HTTPException(400, "Upload chunk has an unexpected size.")
    conn = db.get_conn()
    digest = hashlib.sha256(data).hexdigest()
    with db.tx():
        # An idempotent retry must carry exactly the same bytes.
        conn.execute("INSERT OR IGNORE INTO import_parts(token,kind,part,digest,data) "
                     "SELECT ?, 'raw', ?, ?, ? WHERE EXISTS "
                     "(SELECT 1 FROM import_jobs WHERE token=? AND state='uploading')",
                     (token, part, digest, data, token))
        old = conn.execute("SELECT digest FROM import_parts WHERE token=? AND kind='raw' AND part=?",
                           (token, part)).fetchone()
        if old is None or old[0] != digest:
            raise HTTPException(409, "This chunk was already uploaded with different bytes or the upload is sealed.")
        conn.execute("UPDATE import_jobs SET updated_at=? WHERE token=?", (time.time(), token))
    return {"part": part, "received": len(data)}


@router.post("/uploads/{token}/complete")
def complete(token: str):
    job = _job(token)
    if job["state"] != "uploading":
        return {"token": token, "state": job["state"]}
    conn = db.get_conn()
    row = conn.execute("SELECT COUNT(*),COALESCE(SUM(length(data)),0) FROM import_parts WHERE token=? AND kind='raw'",
                       (token,)).fetchone()
    if row[0] != job["chunks"] or row[1] != job["size"]:
        raise HTTPException(409, "Some upload chunks are missing. Retry the upload.")
    conn.execute("UPDATE import_jobs SET state='validating',updated_at=? WHERE token=? AND state='uploading'",
                 (time.time(), token))
    conn.commit()
    return {"token": token, "state": "validating"}


def status(token):
    job = _job(token)
    out = {"state": job["state"], "updated": job["updated_at"], "error": job["error"],
           "dataset_id": job["dataset_id"]}
    if job["report"]:
        out["report"] = json.loads(job["report"])
    return out


def recheck(token, mapping):
    job = _job(token)
    if job["state"] not in ("ready", "failed") or job["dataset_id"]:
        raise HTTPException(409, "This upload cannot be rechecked while it is processing.")
    conn = db.get_conn()
    conn.execute("UPDATE import_jobs SET state='validating',mapping=?,report=NULL,error=NULL,updated_at=? WHERE token=?",
                 (json.dumps(mapping), time.time(), token))
    conn.commit()


def queue_import(token, name):
    conn = db.get_conn()
    with db.tx(immediate=True):
        # Serialize competing starts; repeating the request returns the same dataset.
        job = _job(token)
        if job["dataset_id"]:
            return {"id": job["dataset_id"], "status": "importing"}
        if job["state"] != "ready":
            raise HTTPException(409, "This file must finish validation first.")
        rep = json.loads(job["report"])
        if not rep.get("accepted_rows"):
            raise HTTPException(400, "No rows passed validation.")
        rep.pop("sample_rows", None)
        cur = conn.execute("INSERT INTO datasets(name,filename,created_at,status,stage,report,total_rows,accepted_rows,rejected_rows) "
                           "VALUES(?,?,?,'importing','Queued for analysis',?,?,?,?)",
                           (name, job["filename"], time.time(), json.dumps(rep), rep["total_rows"],
                            rep["accepted_rows"], rep["rejected_rows"]))
        ds_id = cur.lastrowid
        conn.execute("UPDATE import_jobs SET state='analyzing',dataset_id=?,updated_at=? WHERE token=?",
                     (ds_id, time.time(), token))
    return {"id": ds_id, "status": "importing"}


def _reserve_ids(conn, table, count):
    # Advance SQLite's allocator so concurrent live ingestion cannot use this range.
    row = conn.execute("SELECT seq FROM sqlite_sequence WHERE name=?", (table,)).fetchone()
    base = max(row[0] if row else 0, conn.execute(f"SELECT COALESCE(MAX(id),0) FROM {table}").fetchone()[0])
    if row:
        conn.execute("UPDATE sqlite_sequence SET seq=? WHERE name=?", (base + count, table))
    else:
        conn.execute("INSERT INTO sqlite_sequence(name,seq) VALUES(?,?)", (table, base + count))
    return base


def _validate(job, conn):
    token = job["token"]
    with tempfile.TemporaryDirectory(prefix="vs-validate-") as folder:
        path = str(Path(folder) / job["filename"])
        staged = str(Path(folder) / "staged.tsv.gz")
        _restore(conn, token, "raw", path)
        rep = importer.validate(path, job["filename"], json.loads(job["mapping"]) if job["mapping"] else None, staged)
        conn.execute("DELETE FROM import_parts WHERE token=? AND kind='staged'", (token,))
        _store_file(conn, token, "staged", staged)
        conn.execute("UPDATE import_jobs SET state='ready',report=?,error=NULL WHERE token=?",
                     (json.dumps(rep), token))
        conn.commit()


def _analyze(job, shared):
    token, ds_id = job["token"], job["dataset_id"]
    dataset = dict(shared.execute("SELECT * FROM datasets WHERE id=?", (ds_id,)).fetchone())
    shared.execute("UPDATE datasets SET stage='Analyzing events, detection rules and anomalies',progress=0.05 WHERE id=?", (ds_id,))
    shared.commit()
    with tempfile.TemporaryDirectory(prefix="vs-analysis-") as folder:
        staged = str(Path(folder) / "staged.tsv.gz")
        _restore(shared, token, "staged", staged)
        # Vercel's temporary disk is also occupied by unpacked Python packages.
        # Keep the working database in memory; only compressed logs touch /tmp.
        with db.isolated_database(":memory:") as local:
            cols = list(dataset)
            local.execute(f"INSERT INTO datasets({','.join(cols)}) VALUES({','.join('?' for _ in cols)})", list(dataset.values()))
            local.commit()
            importer.import_staged(ds_id, staged)
            result = dict(local.execute("SELECT * FROM datasets WHERE id=?", (ds_id,)).fetchone())
            shared.execute("BEGIN IMMEDIATE")
            offsets = {t: _reserve_ids(shared, t, local.execute(f"SELECT COALESCE(MAX(id),0) FROM {t}").fetchone()[0])
                       for t in ("sessions", "alerts")}
            shared.execute("DELETE FROM import_parts WHERE token=? AND kind='result'", (token,))
            shared.commit()
            n, pending, pending_bytes = 0, [], 0
            for table in TABLES:
                cur = local.execute(f"SELECT * FROM {table}")
                columns = [d[0] for d in cur.description]
                limit = min(1500, 24000 // len(columns))
                while rows := cur.fetchmany(limit):
                    values = []
                    for row in rows:
                        r = dict(row)
                        if table in offsets:
                            r["id"] += offsets[table]
                        if table in ("alerts", "alert_sessions"):
                            if r.get("session_id") is not None:
                                r["session_id"] += offsets["sessions"]
                            if "alert_id" in r:
                                r["alert_id"] += offsets["alerts"]
                            if "related_sessions" in r:
                                r["related_sessions"] = json.dumps([s + offsets["sessions"] for s in json.loads(r["related_sessions"])])
                        values.append([r[c] for c in columns])
                    data = zlib.compress(json.dumps([table, columns, values], separators=(",", ":")).encode())
                    pending.append((n, data))
                    pending_bytes += len(data)
                    n += 1
                    if pending_bytes >= 512 * 1024:
                        _save_parts(shared, token, "result", pending)
                        shared.execute("UPDATE import_jobs SET lease_until=?,updated_at=? WHERE token=?",
                                       (time.time() + LEASE_SECONDS, time.time(), token))
                        shared.commit()
                        pending, pending_bytes = [], 0
            _save_parts(shared, token, "result", pending)
            for row in local.execute("SELECT version,path FROM models"):
                shared.execute("INSERT OR REPLACE INTO model_files(version,data) VALUES(?,?)",
                               (row["version"], Path(row["path"]).read_bytes()))
            shared.execute("UPDATE import_jobs SET state='publishing',cursor=0,batch_count=?,result=? WHERE token=?",
                           (n, json.dumps(result), token))
            shared.execute("UPDATE datasets SET stage='Saving analysis',progress=0.5 WHERE id=?", (ds_id,))
            shared.commit()


def _publish(job, conn):
    deadline = time.monotonic() + 15
    token, ds_id, cursor = job["token"], job["dataset_id"], job["cursor"]
    while cursor < job["batch_count"] and time.monotonic() < deadline:
        parts = conn.execute("SELECT part,data FROM import_parts WHERE token=? AND kind='result' AND part>=? "
                             "ORDER BY part LIMIT 4", (token, cursor)).fetchall()
        if not parts or [p["part"] for p in parts] != list(range(cursor, cursor + len(parts))):
            raise ValueError("Missing analysis publication batch")
        # Insertion and its checkpoint commit together, so interrupted requests resume
        # without losing rows or publishing duplicates.
        statements = []
        for part in parts:
            table, columns, rows = json.loads(zlib.decompress(bytes(part["data"])))
            if table not in TABLES:
                raise ValueError("Invalid import table")
            statements.append((f"INSERT OR IGNORE INTO {table}({','.join(columns)}) VALUES " +
                               ",".join("(" + ",".join("?" for _ in columns) + ")" for _ in rows), [v for r in rows for v in r]))
        next_cursor = cursor + len(parts)
        statements.append(("UPDATE import_jobs SET cursor=?,updated_at=? WHERE token=?", (next_cursor, time.time(), token)))
        if isinstance(conn, db.RemoteConnection):
            conn.atomic_batch(statements)
        else:
            with db.tx(immediate=True):
                for sql, args in statements:
                    conn.execute(sql, args)
        cursor = next_cursor
    conn.execute("UPDATE datasets SET progress=?,stage=? WHERE id=?",
                 (0.5 + 0.49 * cursor / max(job["batch_count"], 1),
                  f"Saving analysis · {cursor} of {job['batch_count']} batches", ds_id))
    conn.commit()
    if cursor == job["batch_count"]:
        result = json.loads(job["result"])
        cols = ("status", "stage", "progress", "sessions", "alerts", "events", "duplicate_rows", "first_ts", "last_ts", "stats", "error")
        with db.tx():
            conn.execute("UPDATE datasets SET " + ",".join(f"{c}=?" for c in cols) + " WHERE id=?",
                         [result[c] for c in cols] + [ds_id])
            conn.execute("UPDATE import_jobs SET state='done' WHERE token=?", (token,))
            conn.execute("DELETE FROM import_parts WHERE token=?", (token,))


@router.post("/uploads/{token}/process")
def process(token: str):
    conn = db.get_conn()
    job = _job(token)
    if job["state"] not in ("validating", "analyzing", "publishing"):
        return status(token)
    lease = uuid.uuid4().hex
    now = time.time()
    # Claim via an atomic compare-and-swap, not a process-local lock or PID.
    conn.execute("UPDATE import_jobs SET lease=?,lease_until=? WHERE token=? AND COALESCE(lease_until,0)<?",
                 (lease, now + LEASE_SECONDS, token, now))
    conn.commit()
    job = _job(token)
    if job["lease"] != lease:
        return status(token)
    try:
        handler = {"validating": _validate, "analyzing": _analyze, "publishing": _publish}.get(job["state"])
        if handler:
            handler(job, conn)
    except Exception as exc:
        log.exception("import phase %s failed for dataset %s", job["state"], job["dataset_id"])
        try:
            conn.rollback()
        except Exception:
            pass
        if isinstance(conn, db.RemoteConnection):
            db.discard_connection()
            conn = db.get_conn()
        # Infrastructure failures are retryable; validation failures are actionable.
        if job["state"] == "validating" and isinstance(exc, (ValueError, OSError, zipfile.BadZipFile, EOFError)):
            conn.execute("UPDATE import_jobs SET state='failed',error=? WHERE token=?", (str(exc)[:500], token))
            if job["dataset_id"]:
                conn.execute("UPDATE datasets SET status='failed',error=? WHERE id=?", (str(exc)[:500], job["dataset_id"]))
            conn.commit()
        else:
            raise
    finally:
        conn.execute("UPDATE import_jobs SET lease=NULL,lease_until=0,updated_at=? WHERE token=? AND lease=?",
                     (time.time(), token, lease))
        conn.commit()
    return status(token)


def token_for_dataset(ds_id):
    row = db.get_conn().execute("SELECT token FROM import_jobs WHERE dataset_id=?", (ds_id,)).fetchone()
    return row[0] if row else None


@router.post("/{dataset_id}/process")
def process_dataset(dataset_id: int):
    token = token_for_dataset(dataset_id)
    if token:
        return process(token)
    return {"state": "legacy"}


@router.post("/{dataset_id}/retry")
def retry_dataset(dataset_id: int):
    token = token_for_dataset(dataset_id)
    if not token:
        raise HTTPException(409, "This older import cannot resume. Delete it and upload the file again.")
    job = _job(token)
    if job["state"] == "failed":
        conn = db.get_conn()
        with db.tx():
            conn.execute("UPDATE import_jobs SET state=?,error=NULL,lease=NULL,lease_until=0 WHERE token=?",
                         ("publishing" if job["result"] else "analyzing", token))
            conn.execute("UPDATE datasets SET status='importing',error=NULL WHERE id=?", (dataset_id,))
    return {"id": dataset_id}
