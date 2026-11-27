"""Dataset Import: analyze historical Cowrie SSH/Telnet logs offline.

Pipeline (each step runs in its own process so the dashboard stays responsive):

1. Upload    the browser streams one file to disk.
2. Validate  every row is parsed once: checked (eventid, session, timestamp),
             sanitized (passwords, Cowrie's message field and ttylog paths are
             dropped) and written to a compact staged file. The preview report
             with exact accepted/rejected counts comes from this pass.
3. Import    one sequential pass over the staged file stores events, builds
             sessions and runs the per-session rules together, committing in
             short transactions so live ingestion and verdicts never wait long.
             Then the cross-connection rule, anomaly ranking for this dataset,
             and precomputed dashboard statistics.

Accepted files: Cowrie JSON Lines, a JSON array, Elasticsearch-style exports
("_source"), CSV/TSV with a column mapping, and any of these as .gz or .zip.

CLI (very large files):
    python -m voidsentinel.importer /datasets/cowrie.json --name "Kaggle Cowrie"
    python -m voidsentinel.importer /datasets/cowrie.json --preview-only
    python -m voidsentinel.importer /datasets/export.csv --map session=session_id
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from typing import Callable, Iterator

from . import db, fastjson as fj, ml, rules
from .config import settings
from .rules import SEVERITY_RANK, session_findings
from .sanitize import sanitize
from .sessions import iso, rebuild_session, summarize

log = logging.getLogger("vs.import")
csv.field_size_limit(16 * 1024 * 1024)

MAX_ARRAY_BYTES = 400 * 1024 * 1024
REJECT_LABELS = {
    "invalid_json": "Line is not valid JSON",
    "not_object": "JSON value is not an object",
    "missing_eventid": "No eventid field",
    "not_cowrie_event": "eventid does not start with 'cowrie.'",
    "missing_session": "No session field",
    "missing_timestamp": "No timestamp field",
    "bad_timestamp": "Timestamp could not be parsed",
}

# canonical Cowrie field -> header names we recognise automatically (compared without case/_/-/space)
CSV_ALIASES = {
    "eventid": ["eventid", "event_id", "event", "eventtype", "event_type", "type"],
    "session": ["session", "session_id", "sessionid", "sid"],
    "timestamp": ["timestamp", "@timestamp", "time", "datetime", "date_time", "ts", "date"],
    "src_ip": ["src_ip", "source_ip", "srcip", "src", "ip", "client_ip", "remote_ip", "peer_ip"],
    "src_port": ["src_port", "source_port", "srcport", "sport"],
    "dst_port": ["dst_port", "dest_port", "destination_port", "dport"],
    "protocol": ["protocol", "proto"],
    "username": ["username", "user", "login", "user_name"],
    "input": ["input", "command", "cmd", "commands"],
    "url": ["url", "download_url"],
    "shasum": ["shasum", "sha256", "hash"],
    "duration": ["duration"],
    "duration_ms": ["duration_ms"],
    "version": ["version", "client_version", "ssh_version"],
    "sensor": ["sensor", "honeypot", "hostname", "host"],
}
MAPPABLE = list(CSV_ALIASES)
REQUIRED = ("eventid", "session", "timestamp")
SECRET_HEADERS = {"password", "pass", "passwd", "pwd", "message", "msg", "ttylog"}
INT_FIELDS = {"src_port", "dst_port"}
EVENT_PREFIX = re.compile(r"^(session|client|login|command|log|direct-tcpip)\.")


def _norm(h: str) -> str:
    return re.sub(r"[\s_\-]", "", (h or "").strip().lower())


def suggest_mapping(headers: list[str]) -> dict:
    by_norm = {_norm(h): h for h in headers}
    out = {}
    for field, aliases in CSV_ALIASES.items():
        for a in aliases:
            if _norm(a) in by_norm:
                out[field] = by_norm[_norm(a)]
                break
    return out


MAPPABLE = list(CSV_ALIASES)
REQUIRED = ("eventid", "session", "timestamp")
SECRET_HEADERS = {"password", "pass", "passwd", "pwd", "message", "msg", "ttylog"}
INT_FIELDS = {"src_port", "dst_port"}
EVENT_PREFIX = re.compile(r"^(session|client|login|command|log|direct-tcpip)\.")
ISO_Z = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z$")


def _norm(h: str) -> str:
    return re.sub(r"[\s_\-]", "", (h or "").strip().lower())


def suggest_mapping(headers: list[str]) -> dict:
    by_norm = {_norm(h): h for h in headers}
    out = {}
    for field, aliases in CSV_ALIASES.items():
        for a in aliases:
            if _norm(a) in by_norm:
                out[field] = by_norm[_norm(a)]
                break
    return out


def is_csv(name: str) -> bool:
    n = name.lower()
    return n.endswith((".csv", ".csv.gz", ".tsv", ".tsv.gz"))


def _looks_like_log(name: str) -> bool:
    base = os.path.basename(name).lower()
    return not name.endswith("/") and (base.endswith((".json", ".jsonl", ".log", ".csv", ".tsv", ".gz"))
                                       or "cowrie.json" in base)


# ------------------------------------------------------------------ reading
class _Progress:
    """Tracks characters read against an estimated total, for the progress bar."""

    def __init__(self, total: int):
        self.total = max(total, 1)
        self.done = 0

    @property
    def fraction(self) -> float:
        return min(self.done / self.total, 0.999)


def _iter_text(fh, source: str, prog: _Progress) -> Iterator[tuple[str, int, str]]:
    """JSON Lines (fast C-level line iteration) or a JSON array."""
    head = fh.read(8192)
    if head.lstrip().startswith("["):
        rest = fh.read(MAX_ARRAY_BYTES)
        if fh.read(1):
            raise ValueError("JSON array files above 400 MB are not supported; convert to JSON Lines "
                             "(e.g. jq -c '.[]' file.json > file.jsonl).")
        prog.done += len(head) + len(rest)
        for i, item in enumerate(json.loads(head + rest), 1):
            yield source, i, json.dumps(item)
        return
    first = head + fh.readline()  # complete the line cut by the 8 KB peek
    n = 0
    for chunk in (io.StringIO(first), fh):
        for line in chunk:
            n += 1
            prog.done += len(line)
            if line.strip():
                yield source, n, line.rstrip("\r\n")


def _iter_csv(fh, source: str, mapping: dict | None, meta: dict, prog: _Progress):
    sample = fh.read(65536)
    try:
        dialect = csv.Sniffer().sniff(sample.split("\n", 1)[0], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel

    def lines():
        for chunk in (io.StringIO(sample + fh.readline()), fh):
            for line in chunk:
                prog.done += len(line)
                yield line
    reader = csv.reader(lines(), dialect)
    headers = next(reader, None) or []
    meta.setdefault("headers", headers)
    m = mapping if mapping is not None else suggest_mapping(headers)
    meta.setdefault("mapping", m)
    idx = {field: headers.index(h) for field, h in m.items() if h in headers}
    secret_idx = [i for i, h in enumerate(headers) if _norm(h) in SECRET_HEADERS]
    for line_no, row in enumerate(reader, 2):
        if not row or not any(c.strip() for c in row):
            continue
        obj = {}
        for field, i in idx.items():
            if i < len(row) and row[i].strip() != "":
                v = row[i].strip()
                if field in INT_FIELDS:
                    try:
                        v = int(float(v))
                    except ValueError:
                        pass
                obj[field] = v
        secrets_present = [headers[i] for i in secret_idx if i < len(row) and row[i].strip()]
        yield source, line_no, {"__csv__": obj, "__secrets__": secrets_present}


def _text(raw, gz: bool):
    return io.TextIOWrapper(gzip.GzipFile(fileobj=raw) if gz else raw, encoding="utf-8", errors="replace", newline="")


def iter_records(path: str, display_name: str | None = None, mapping: dict | None = None,
                 meta: dict | None = None, prog: _Progress | None = None):
    """Yield (source, line_no, payload): JSON text, or a mapped CSV row."""
    meta = meta if meta is not None else {}
    name = (display_name or os.path.basename(path)).lower()
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            members = sorted((i for i in zf.infolist() if _looks_like_log(i.filename)), key=lambda i: i.filename)
            if not members:
                raise ValueError("The zip contains no .json, .jsonl, .log, .csv or cowrie.json* files.")
            est = sum(i.file_size * (6 if i.filename.endswith(".gz") else 1) for i in members)
            prog = prog or _Progress(est)
            prog.total = est
            meta["members"] = [i.filename for i in members]
            for info in members:
                with zf.open(info) as raw:
                    fh = _text(raw, info.filename.endswith(".gz"))
                    if is_csv(info.filename):
                        meta["format"] = "csv"
                        yield from _iter_csv(fh, info.filename, mapping, meta, prog)
                    else:
                        meta.setdefault("format", "json")
                        yield from _iter_text(fh, info.filename, prog)
        return
    size = os.path.getsize(path)
    with open(path, "rb") as raw:
        gz = raw.read(2) == b"\x1f\x8b"
        raw.seek(0)
        prog = prog or _Progress(size * (6 if gz else 1))
        prog.total = size * (6 if gz else 1)
        fh = _text(raw, gz)
        if is_csv(name):
            meta["format"] = "csv"
            yield from _iter_csv(fh, os.path.basename(path), mapping, meta, prog)
        else:
            meta["format"] = "json"
            yield from _iter_text(fh, os.path.basename(path), prog)


# ------------------------------------------------------------------ validation
def strict_ts(value) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        v = float(value)
        return v / 1000.0 if v > 1e11 else v  # epoch milliseconds or seconds
    if isinstance(value, str) and value.strip():
        v = value.strip()
        if v[0].isdigit() and re.fullmatch(r"\d{9,13}(\.\d+)?", v):
            return strict_ts(float(v))
        v = v.replace("Z", "+00:00")
        if " " in v and "T" not in v:
            v = v.replace(" ", "T", 1)
        try:
            dt = datetime.fromisoformat(v)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return None


def check(payload) -> tuple[dict | None, str | None, dict]:
    """Return (sanitized record, reject reason, flags). payload: JSON text or mapped CSV row."""
    flags: dict = {}
    if isinstance(payload, dict) and "__csv__" in payload:
        obj = dict(payload["__csv__"])
        present = {_norm(h) for h in payload["__secrets__"]}
        flags["password"] = bool(present & {"password", "pass", "passwd", "pwd"})
        flags["message"] = bool(present & {"message", "msg"})
        flags["ttylog"] = "ttylog" in present
    else:
        try:
            obj = fj.loads(payload)
        except ValueError:
            return None, "invalid_json", flags
        if not isinstance(obj, dict):
            return None, "not_object", flags
        if isinstance(obj.get("_source"), dict) and "eventid" not in obj:
            obj = obj["_source"]
        flags["password"] = "password" in obj
        flags["message"] = "message" in obj
        flags["ttylog"] = "ttylog" in obj
    eventid = obj.get("eventid")
    if not isinstance(eventid, str) or not eventid.strip():
        return None, "missing_eventid", flags
    eventid = eventid.strip()
    if not eventid.startswith("cowrie."):
        if not EVENT_PREFIX.match(eventid):
            return None, "not_cowrie_event", flags
        eventid = "cowrie." + eventid  # exports that dropped the prefix
        flags["prefixed"] = True
    obj["eventid"] = eventid
    sess = obj.get("session")
    if sess is None or str(sess).strip() == "":
        return None, "missing_session", flags
    raw_ts = obj.get("timestamp")
    if raw_ts is None:
        return None, "missing_timestamp", flags
    ts = strict_ts(raw_ts)
    if ts is None:
        return None, "bad_timestamp", flags
    flags["sensor"] = str(obj.get("sensor") or "unknown")[:60]
    rec = sanitize(obj)
    rec["session"] = str(sess)[:64]
    rec["timestamp"] = raw_ts if isinstance(raw_ts, str) and ISO_Z.match(raw_ts) else iso(ts)
    flags["ts"] = ts
    return rec, None, flags


def _clean_field(v) -> str:
    return str(v).replace("\t", " ").replace("\n", " ").replace("\r", " ")


def validate(path: str, display_name: str, mapping: dict | None = None, staged_path: str | None = None,
             on_progress: Callable[[float, int], None] | None = None) -> dict:
    """One pass: validate + sanitize every row, write the staged file, return the preview report."""
    t0 = time.time()
    total = accepted = prefixed = 0
    reasons: Counter = Counter()
    reason_samples: dict[str, list] = {}
    eventids: Counter = Counter()
    protocols: Counter = Counter()
    sensors: Counter = Counter()
    sessions: set = set()
    src_ips: set = set()
    stripped = Counter()
    no_src = 0
    first = last = None
    samples = []
    meta: dict = {}
    prog = _Progress(1)
    out = open(staged_path, "w", encoding="utf-8") if staged_path else None
    last_report = 0.0
    try:
        for source, line_no, payload in iter_records(path, display_name, mapping, meta, prog):
            total += 1
            rec, reason, flags = check(payload)
            if reason:
                reasons[reason] += 1
                if len(reason_samples.setdefault(reason, [])) < 5:
                    text = payload if isinstance(payload, str) else json.dumps(payload["__csv__"])
                    reason_samples[reason].append({"file": source, "line": line_no, "text": text[:160]})
                continue
            accepted += 1
            if flags.get("prefixed"):
                prefixed += 1
            eid = rec["eventid"]
            eventids[eid] += 1
            sensors[flags["sensor"]] += 1
            proto = rec.get("protocol")
            if proto:
                protocols[proto] += 1
            sessions.add(hash((flags["sensor"], rec["session"])))
            src = rec.get("src_ip")
            if src:
                src_ips.add(hash(src))
            else:
                no_src += 1
            if flags["password"]:
                stripped["password"] += 1
            if flags["message"]:
                stripped["message"] += 1
            if flags["ttylog"]:
                stripped["ttylog"] += 1
            ts = flags["ts"]
            if first is None or ts < first:
                first = ts
            if last is None or ts > last:
                last = ts
            if len(samples) < 6:
                samples.append(rec)
            if out:
                raw = payload if isinstance(payload, str) else json.dumps(payload["__csv__"], sort_keys=True)
                h = hashlib.blake2b(raw.encode("utf-8", "replace"), digest_size=10).hexdigest()
                out.write(f"{h}\t{_clean_field(flags['sensor'])}\t{_clean_field(rec['session'])}\t{eid}\t{ts!r}\t"
                          f"{_clean_field(src or '')}\t{fj.dumps(rec)}\n")
            if on_progress and total % 5000 == 0 and time.time() - last_report > 0.5:
                on_progress(prog.fraction, total)
                last_report = time.time()
    finally:
        if out:
            out.close()
    login_or_session = sum(v for k, v in eventids.items() if k.startswith(("cowrie.session.", "cowrie.login.")))
    fmt = meta.get("format", "json")
    problem = None
    if total == 0:
        problem = "The file has no rows."
    elif accepted == 0 and fmt == "csv":
        missing = [f for f in REQUIRED if f not in meta.get("mapping", {})]
        problem = ("No row passed validation. " + (f"Map these columns first: {', '.join(missing)}."
                                                   if missing else "Check the column mapping below."))
    elif accepted == 0:
        problem = ("No row passed validation. Each event needs eventid (cowrie.*), session and timestamp. "
                   "Is this a Cowrie event log?")
    elif not login_or_session:
        problem = "No connection or login events were found, so session timelines will be thin."
    n_sessions = len(sessions)
    rate = total / max(time.time() - t0, 0.001)
    return {
        "filename": display_name,
        "format": fmt,
        "members": meta.get("members"),
        "csv": {"headers": meta.get("headers", []), "mapping": meta.get("mapping", {}),
                "suggested": suggest_mapping(meta.get("headers", [])), "fields": MAPPABLE,
                "required": list(REQUIRED)} if fmt == "csv" else None,
        "size_bytes": os.path.getsize(path),
        "total_rows": total,
        "accepted_rows": accepted,
        "rejected_rows": total - accepted,
        "prefixed_eventids": prefixed,
        "rejections": [{"reason": r, "label": REJECT_LABELS[r], "count": c, "samples": reason_samples[r]}
                       for r, c in reasons.most_common()],
        "eventids": dict(eventids.most_common()),
        "sessions": n_sessions,
        "source_ips": len(src_ips),
        "rows_without_src_ip": no_src,
        "protocols": dict(protocols),
        "sensors": dict(sensors.most_common(20)),
        "first_ts": first, "last_ts": last,
        "stripped": {"password_fields": stripped["password"], "message_fields": stripped["message"],
                     "ttylog_fields": stripped["ttylog"]},
        "sample_rows": samples,
        "usable": accepted > 0 and login_or_session > 0,
        "problem": problem,
        "ml_note": (None if n_sessions >= settings.ml_min_train else
                    f"Only {n_sessions} sessions: anomaly ranking needs at least {settings.ml_min_train}. "
                    "Rules and timelines still work."),
        "seconds": round(time.time() - t0, 2),
        "estimated_import_seconds": round(accepted / 60000 + 3, 0),
        "rows_per_second": round(rate),
    }


def preview(path: str, display_name: str, mapping: dict | None = None) -> dict:
    """Validation report only (no staged file)."""
    return validate(path, display_name, mapping)


# ------------------------------------------------------------------ uploads (status files)
def uploads_dir() -> str:
    d = os.path.join(settings.data_dir, "uploads")
    os.makedirs(d, exist_ok=True)
    return d


def new_upload(filename: str) -> tuple[str, str]:
    """Reserve a folder for an upload. Returns (token, destination path)."""
    token = uuid.uuid4().hex
    safe = os.path.basename(filename).replace("/", "_").replace("\\", "_")[:120] or "upload.json"
    if safe.startswith("."):
        safe = "upload" + safe
    folder = os.path.join(uploads_dir(), token)
    os.makedirs(folder)
    return token, os.path.join(folder, safe)


def _folder(token: str) -> str:
    if not token.isalnum():
        raise ValueError("bad token")
    return os.path.join(uploads_dir(), token)


def upload_path(token: str) -> str:
    folder = _folder(token)
    files = [f for f in os.listdir(folder) if not f.startswith(".") and f != "staged.tsv"] if os.path.isdir(folder) else []
    if not files:
        raise FileNotFoundError("Upload not found or already imported. Upload the file again.")
    return os.path.join(folder, files[0])


def write_status(token: str, **status) -> None:
    folder = _folder(token)
    tmp = os.path.join(folder, ".status.tmp")
    with open(tmp, "w") as fh:
        json.dump({**status, "updated": time.time()}, fh, default=str)
    os.replace(tmp, os.path.join(folder, ".status.json"))


def read_status(token: str) -> dict:
    try:
        with open(os.path.join(_folder(token), ".status.json")) as fh:
            st = json.load(fh)
    except FileNotFoundError:
        raise FileNotFoundError("Upload not found. Upload the file again.")
    if st.get("state") == "validating" and st.get("pid") and not _alive(st["pid"]) and time.time() - st["updated"] > 5:
        st = {"state": "failed", "error": "Validation stopped unexpectedly. Upload the file again."}
    return st


def _alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
    except (OSError, ValueError):
        return False
    try:  # a finished child that hasn't been reaped yet is not "alive"
        with open(f"/proc/{int(pid)}/stat") as fh:
            return fh.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return True


def _spawn(args: list[str], log_path: str) -> int:
    """Run heavy work in its own process: the API stays responsive."""
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    logf = open(log_path, "a")
    proc = subprocess.Popen([sys.executable, "-m", "voidsentinel.importer", *args], cwd=pkg_parent,
                            stdout=logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            start_new_session=True, env=os.environ.copy())
    threading.Thread(target=proc.wait, daemon=True).start()  # reap when done
    return proc.pid


def start_validation(token: str, mapping: dict | None = None) -> None:
    folder = _folder(token)
    if mapping is not None:
        with open(os.path.join(folder, ".mapping.json"), "w") as fh:
            json.dump(mapping, fh)
    write_status(token, state="validating", progress=0, rows=0)
    pid = _spawn(["--validate-token", token], os.path.join(folder, ".validate.log"))
    write_status(token, state="validating", progress=0, rows=0, pid=pid)


def _run_validation(token: str) -> None:
    folder = _folder(token)
    path = upload_path(token)
    mapping = None
    if os.path.exists(os.path.join(folder, ".mapping.json")):
        with open(os.path.join(folder, ".mapping.json")) as fh:
            mapping = json.load(fh)
    pid = os.getpid()
    try:
        rep = validate(path, os.path.basename(path), mapping, os.path.join(folder, "staged.tsv"),
                       lambda f, n: write_status(token, state="validating", progress=round(f, 3), rows=n, pid=pid))
        with open(os.path.join(folder, ".report.json"), "w") as fh:
            json.dump(rep, fh, default=str)
        write_status(token, state="ready", progress=1, rows=rep["total_rows"])
    except Exception as exc:
        log.exception("validation failed")
        write_status(token, state="failed", error=f"Could not read this file: {exc}")


def read_report(token: str) -> dict | None:
    try:
        with open(os.path.join(_folder(token), ".report.json")) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def cleanup_uploads(max_age_hours: float = 24) -> None:
    root = uploads_dir()
    for name in os.listdir(root):
        p = os.path.join(root, name)
        try:
            if time.time() - os.path.getmtime(p) > max_age_hours * 3600:
                shutil.rmtree(p, ignore_errors=True)
        except OSError:
            pass


# ------------------------------------------------------------------ import
def create_dataset(name: str, filename: str, report: dict | None) -> int:
    conn = db.get_conn()
    rep = {k: v for k, v in (report or {}).items() if k != "sample_rows"}
    cur = conn.execute(
        "INSERT INTO datasets(name, filename, created_at, status, stage, report, total_rows, accepted_rows, "
        "rejected_rows) VALUES (?,?,?,?,?,?,?,?,?)",
        (name, filename, time.time(), "importing", "Queued", json.dumps(rep, default=str),
         rep.get("total_rows", 0), rep.get("accepted_rows", 0), rep.get("rejected_rows", 0)))
    conn.commit()
    return cur.lastrowid


def start_import(ds_id: int, token: str) -> None:
    pid = _spawn(["--import-dataset", str(ds_id), "--token", token], os.path.join(_folder(token), ".import.log"))
    conn = db.get_conn()
    conn.execute("UPDATE datasets SET pid=? WHERE id=?", (pid, ds_id))
    conn.commit()


def running_import() -> dict | None:
    row = db.get_conn().execute("SELECT id, name, pid FROM datasets WHERE status='importing'").fetchone()
    return dict(row) if row and _alive(row["pid"]) else None


class _Stats:
    """Dashboard numbers gathered during the pass, so viewing a dataset never scans its events."""

    def __init__(self):
        self.minute = Counter()     # (minute, kind) -> count
        self.users = Counter()
        self.users_ok = Counter()
        self.cmds = Counter()
        self.ev = Counter()
        self.outcomes = Counter()
        self.src = {}               # ip -> [sessions, failed, commands]

    @staticmethod
    def _prune(c: Counter, cap: int = 200_000, keep: int = 20_000):
        if len(c) > cap:
            top = c.most_common(keep)
            c.clear()
            c.update(dict(top))

    def event(self, eid: str, ts: float, rec: dict):
        m = int(ts // 60) * 60
        if eid == "cowrie.session.connect":
            self.minute[(m, "connections")] += 1
        elif eid == "cowrie.login.failed":
            self.ev["failed"] += 1
            self.minute[(m, "failed_logins")] += 1
            self.users[rec.get("username")] += 1
        elif eid == "cowrie.login.success":
            self.ev["success"] += 1
            self.users[rec.get("username")] += 1
            self.users_ok[rec.get("username")] += 1
        elif eid == "cowrie.command.input":
            self.ev["commands"] += 1
            self.minute[(m, "commands")] += 1
            self.cmds[rec.get("input")] += 1
        if len(self.users) > 200_000:
            self._prune(self.users)
        if len(self.cmds) > 200_000:
            self._prune(self.cmds)

    def session(self, s: dict):
        self.outcomes[s["outcome"]] += 1
        ip = s["src_ip"]
        if ip:
            v = self.src.setdefault(ip, [0, 0, 0])
            v[0] += 1
            v[1] += s["login_failed"]
            v[2] += s["command_count"]

    def finish(self, conn, ds_id: int, first: float, last: float) -> dict:
        span = max((last or 0) - (first or 0), 1)
        bucket = (60 if span <= 6 * 3600 else 3600 if span <= 3 * 86400 else 86400 if span <= 180 * 86400
                  else 7 * 86400)
        series: dict[int, dict] = {}
        start = int((first or 0) // bucket) * bucket
        for b in range(start, int(last or 0) + 1, bucket):
            series[b] = {"t": b, "connections": 0, "failed_logins": 0, "commands": 0}
        for (m, kind), c in self.minute.items():
            b = int(m // bucket) * bucket
            if b in series:
                series[b][kind] += c
        top_src = sorted(self.src.items(), key=lambda kv: (-kv[1][0], -kv[1][1]))[:8]
        top_sources = []
        for ip, (n, f, c) in top_src:
            sev = conn.execute("SELECT MAX(max_severity) FROM sessions WHERE dataset_id=? AND src_ip=?",
                               (ds_id, ip)).fetchone()[0] or 0
            top_sources.append({"src_ip": ip, "sessions": n, "failed_logins": f, "commands": c,
                                "max_severity": sev, "is_demo": 0})
        total = sum(self.outcomes.values())
        return {
            "sessions": {"total": total, "interactive": self.outcomes["interactive"],
                         "auth_failed": self.outcomes["auth_failed"], "no_auth": self.outcomes["no_auth"],
                         "login_no_commands": self.outcomes["login_no_commands"],
                         "sources": len(self.src), "demo": 0},
            "events": {"failed": self.ev["failed"], "success": self.ev["success"], "commands": self.ev["commands"]},
            "series": {"bucket_seconds": bucket, "points": list(series.values())},
            "top_sources": top_sources,
            "top_usernames": [{"username": u, "attempts": n, "accepted": self.users_ok.get(u, 0)}
                              for u, n in self.users.most_common(8)],
            "top_commands": [{"command": c, "count": n} for c, n in self.cmds.most_common(8)],
        }


IDLE_LINES = 200_000  # a session untouched for this many rows is treated as complete


def _progress(conn, ds_id, stage, progress, **extra):
    sets = "".join(f", {k}=?" for k in extra)
    conn.execute(f"UPDATE datasets SET stage=?, progress=?{sets} WHERE id=?",
                 (stage, round(progress, 3), *extra.values(), ds_id))
    conn.commit()


def import_staged(ds_id: int, staged_path: str) -> None:
    db.init()
    conn = db.get_conn()
    conn.execute("PRAGMA cache_size=-262144")   # 256 MB page cache for this bulk load
    conn.execute("PRAGMA temp_store=MEMORY")
    try:
        _import(conn, ds_id, staged_path)
    except Exception as exc:
        log.exception("import %s failed", ds_id)
        conn.rollback()
        conn.execute("UPDATE datasets SET status='failed', error=? WHERE id=?",
                     (f"Import failed: {str(exc)[:400]}", ds_id))
        conn.commit()
        raise


SESSION_COLS = ("src_ip", "src_port", "start_ts", "end_ts", "last_event_ts", "status", "closed_reason",
                "duration", "client_version", "event_count", "login_failed", "login_success", "username",
                "usernames", "command_count", "commands_failed", "first_command_ts", "categories",
                "download_count", "outcome", "mean_gap", "protocol")
INSERT_SESSION = (f"INSERT INTO sessions(sensor, session, dataset_id, is_demo, alert_count, max_severity, "
                  f"{', '.join(SESSION_COLS)}) VALUES (?,?,?,0,?,?,{','.join('?' * len(SESSION_COLS))}) "
                  f"ON CONFLICT(sensor, session) DO NOTHING RETURNING id")
INSERT_EVENT = ("INSERT OR IGNORE INTO events(event_uid, cw_event_id, sensor, session, eventid, ts, ts_iso, "
                "src_ip, data, ingested_at, dataset_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)")


def _import(conn, ds_id: int, staged_path: str) -> None:
    row = conn.execute("SELECT accepted_rows FROM datasets WHERE id=?", (ds_id,)).fetchone()
    expected = max(row["accepted_rows"] or 1, 1)
    prefix = f"ds{ds_id}"
    stats = _Stats()
    open_s: dict[tuple, dict] = {}
    done_keys: set[int] = set()
    late: set[tuple] = set()
    batch: list[tuple] = []
    n = inserted = n_sessions = n_alerts = 0
    first = last = None
    last_commit = time.time()
    now = time.time()
    t_phase = time.time()

    def phase(name):
        nonlocal t_phase
        log.info("phase %-28s %6.1fs", name, time.time() - t_phase)
        t_phase = time.time()

    def flush_events():
        nonlocal inserted, batch
        if batch:
            before = conn.total_changes
            conn.executemany(INSERT_EVENT, batch)
            inserted += conn.total_changes - before
            batch = []

    def finish(key, entry):
        nonlocal n_sessions, n_alerts
        evs = entry["events"]
        evs.sort(key=lambda e: e["_ts"])
        s = summarize(evs)
        if s["status"] == "open":
            s["status"], s["closed_reason"] = "closed", "import_end"
        findings = session_findings(evs)
        sev = max((SEVERITY_RANK[f["severity"]] for f in findings), default=0)
        vals = [json.dumps(s[c]) if c in ("usernames", "categories") else s[c] for c in SESSION_COLS]
        r = conn.execute(INSERT_SESSION, (key[0], key[1], ds_id, len(findings), sev, *vals)).fetchone()
        if r is None:  # session already stored (e.g. re-run): rebuild it from the database later
            late.add(key)
            return
        sid = r[0]
        for f in findings:
            rules._upsert_alert(conn, f"{f['rule_id']}:{key[0]}:{key[1]}", f, key[0], sid, s["src_ip"], [sid], ds_id)
        n_alerts += len(findings)
        n_sessions += 1
        stats.session(s)
        done_keys.add(hash(key))

    with open(staged_path, "r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t", 6)
            if len(parts) != 7:
                continue
            h, sensor, session, eid, ts_s, src, data = parts
            ts = float(ts_s)
            n += 1
            key = (f"{prefix}/{sensor}", session)
            rec = fj.loads(data)
            uid = f"{ds_id:x}:{int(ts * 1000):011x}{h}"
            batch.append((uid, None, key[0], session, eid, ts, rec["timestamp"], src or None, data, now, ds_id))
            stats.event(eid, ts, rec)
            first = ts if first is None or ts < first else first
            last = ts if last is None or ts > last else last
            if hash(key) in done_keys:
                late.add(key)  # event for a session already finished: fix it up from the database later
            else:
                entry = open_s.get(key)
                if entry is None:
                    entry = open_s[key] = {"events": [], "uids": set(), "line": n}
                if uid not in entry["uids"]:  # identical duplicate rows count once
                    entry["uids"].add(uid)
                    rec["_uid"], rec["_ts"] = uid, ts
                    entry["events"].append(rec)
                entry["line"] = n
            if len(batch) >= 20000:
                flush_events()
            if n % 50000 == 0:
                stale = [k for k, e in open_s.items() if n - e["line"] > IDLE_LINES]
                for k in stale:
                    finish(k, open_s.pop(k))
            if time.time() - last_commit > 1.0:
                flush_events()
                _progress(conn, ds_id, f"Storing events and building sessions · {n:,} of {expected:,} rows",
                          0.8 * n / expected)
                last_commit = time.time()
    flush_events()
    for k in list(open_s):
        finish(k, open_s.pop(k))
    conn.commit()

    phase("events + sessions + rules")
    if late:  # rare: sessions whose events were far apart in the file
        _progress(conn, ds_id, f"Re-checking {len(late):,} sessions split across the file", 0.8)
        for sensor, session in late:
            sid = rebuild_session(conn, sensor, session, dataset_id=ds_id)
            if sid:
                rules.run_session_rules(conn, sid)
        conn.execute("UPDATE sessions SET status='closed', closed_reason='import_end' "
                     "WHERE dataset_id=? AND status='open'", (ds_id,))
        conn.commit()

    # cross-connection rule: one ordered pass over failed logins
    _progress(conn, ds_id, "Checking repeated login failures per source", 0.82,
              events=inserted, duplicate_rows=n - inserted, first_ts=first, last_ts=last)
    with closing(db.connect()) as source_conn:
        cur = source_conn.execute(
            "SELECT src_ip, event_uid, ts, sensor, session FROM events WHERE dataset_id=? "
            "AND eventid='cowrie.login.failed' AND src_ip IS NOT NULL ORDER BY src_ip, ts", (ds_id,))
        ip, rows_ip = None, []
        for r in cur:
            if r["src_ip"] != ip:
                if rows_ip:
                    rules.emit_source_bursts(conn, ip, rows_ip, ds_id)
                ip, rows_ip = r["src_ip"], []
                if time.time() - last_commit > 1.0:
                    conn.commit()
                    last_commit = time.time()
            rows_ip.append(r)
        if rows_ip:
            rules.emit_source_bursts(conn, ip, rows_ip, ds_id)
    conn.commit()

    phase("cross-connection rule")
    _progress(conn, ds_id, "Ranking unusual sessions", 0.88)
    result = ml.train_and_activate(conn, f"ds:{ds_id}", commit_chunks=True)
    if not result.get("trained"):
        ml.rescore_all(conn, f"ds:{ds_id}", commit_chunks=True)
    phase("anomaly ranking")
    _progress(conn, ds_id, "Preparing dashboard summaries", 0.97)
    sessions = conn.execute("SELECT COUNT(*) FROM sessions WHERE dataset_id=?", (ds_id,)).fetchone()[0]
    alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE dataset_id=?", (ds_id,)).fetchone()[0]
    summary = stats.finish(conn, ds_id, first, last)
    stage = "Ready" if result.get("trained") else \
        f"Ready. Anomaly ranking skipped: {result.get('reason')} Rules and timelines are available."
    conn.execute("UPDATE datasets SET status='ready', stage=?, progress=1, sessions=?, alerts=?, events=?, "
                 "duplicate_rows=?, first_ts=?, last_ts=?, stats=?, error=NULL WHERE id=?",
                 (stage, sessions, alerts, inserted, n - inserted, first, last, json.dumps(summary), ds_id))
    conn.commit()
    log.info("dataset %s ready: %s rows, %s events, %s sessions, %s alerts", ds_id, n, inserted, sessions, alerts)


def delete_dataset(ds_id: int) -> None:
    conn = db.get_conn()
    paths = [r["path"] for r in conn.execute("SELECT path FROM models WHERE scope=?", (f"ds:{ds_id}",))]
    conn.execute("DELETE FROM alert_sessions WHERE alert_id IN (SELECT id FROM alerts WHERE dataset_id=?)", (ds_id,))
    for table in ("alerts", "sessions", "events"):
        conn.execute(f"DELETE FROM {table} WHERE dataset_id=?", (ds_id,))
    conn.execute("DELETE FROM model_files WHERE version IN (SELECT version FROM models WHERE scope=?)", (f"ds:{ds_id}",))
    conn.execute("DELETE FROM import_parts WHERE token IN (SELECT token FROM import_jobs WHERE dataset_id=?)", (ds_id,))
    conn.execute("DELETE FROM import_jobs WHERE dataset_id=?", (ds_id,))
    conn.execute("DELETE FROM models WHERE scope=?", (f"ds:{ds_id}",))
    conn.execute("DELETE FROM datasets WHERE id=?", (ds_id,))
    conn.commit()
    ml._cache.pop(f"ds:{ds_id}", None)
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def mark_interrupted() -> None:
    """At API start: imports whose process is gone cannot resume."""
    conn = db.get_conn()
    for r in conn.execute("SELECT id, pid FROM datasets WHERE status='importing' AND id NOT IN "
                          "(SELECT dataset_id FROM import_jobs WHERE dataset_id IS NOT NULL)").fetchall():
        if not _alive(r["pid"]):
            conn.execute("UPDATE datasets SET status='failed', error='The import stopped before finishing "
                         "(the service restarted). Delete this dataset and import the file again.' WHERE id=?",
                         (r["id"],))
    conn.commit()


# ------------------------------------------------------------------ CLI
def main():
    ap = argparse.ArgumentParser(description="Import a Cowrie log into VoidSentinel")
    ap.add_argument("path", nargs="?")
    ap.add_argument("--name", help="Dataset name shown in the dashboard")
    ap.add_argument("--preview-only", action="store_true")
    ap.add_argument("--map", action="append", default=[], metavar="FIELD=COLUMN",
                    help="CSV only: map a Cowrie field to a column, e.g. --map session=session_id")
    ap.add_argument("--validate-token", help=argparse.SUPPRESS)
    ap.add_argument("--import-dataset", type=int, help=argparse.SUPPRESS)
    ap.add_argument("--token", help=argparse.SUPPRESS)
    args = ap.parse_args()
    logging.basicConfig(level="INFO", format="%(asctime)s %(name)s %(levelname)s %(message)s")
    db.init()

    if args.validate_token:                       # spawned by the API
        _run_validation(args.validate_token)
        return
    if args.import_dataset:                       # spawned by the API
        folder = _folder(args.token)
        try:
            import_staged(args.import_dataset, os.path.join(folder, "staged.tsv"))
        finally:
            shutil.rmtree(folder, ignore_errors=True)
        return

    if not args.path:
        ap.error("path is required")
    mapping = None
    if args.map:
        meta: dict = {}
        for _ in iter_records(args.path, os.path.basename(args.path), None, meta):
            break
        mapping = dict(meta.get("mapping", {}))
        for item in args.map:
            k, _, v = item.partition("=")
            mapping[k.strip()] = v.strip()
    name = os.path.basename(args.path)
    staged = os.path.join(uploads_dir(), f"cli-{uuid.uuid4().hex}.tsv")
    t0 = time.time()
    rep = validate(args.path, name, mapping, None if args.preview_only else staged,
                   lambda f, n: print(f"\rvalidating… {f * 100:5.1f}%  {n:,} rows", end="", flush=True))
    print()
    print(json.dumps({k: v for k, v in rep.items() if k != "sample_rows"}, indent=2, default=str))
    if args.preview_only or not rep["accepted_rows"]:
        return
    try:
        ds_id = create_dataset(args.name or name, name, rep)
        import_staged(ds_id, staged)
    finally:
        if os.path.exists(staged):
            os.remove(staged)
    row = db.get_conn().execute("SELECT status, stage, events, sessions, alerts, error FROM datasets WHERE id=?",
                                (ds_id,)).fetchone()
    print(f"dataset {ds_id}: {dict(row)}  ({time.time() - t0:.1f}s total)")


if __name__ == "__main__":
    main()
