"""Where sanitized sensor events come from.

Both sources return (event_uid, cloudwatch_event_id, record) tuples plus a
pending checkpoint that the worker persists in the same transaction as the
events. Re-reads are harmless: events are de-duplicated by event_uid.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time

from . import db
from .config import settings
from .sanitize import sanitize

log = logging.getLogger("vs.sources")


def _uid_for(record: dict, fallback: str) -> str:
    uid = record.get("vs_uid")
    if isinstance(uid, str) and 8 <= len(uid) <= 64:
        return uid
    return hashlib.sha256(fallback.encode()).hexdigest()[:32]


def _parse(message: str) -> dict | None:
    try:
        rec = json.loads(message)
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict) or "eventid" not in rec:
        return None
    # Defence in depth: re-apply the allowlist even though the sensor already did.
    uid = rec.get("vs_uid")
    clean = sanitize(rec)
    if uid:
        clean["vs_uid"] = uid
    return clean


class FileSource:
    """Reads the JSONL file written by the collector in lab mode."""

    name = "file"

    def __init__(self, path: str):
        self.path = path
        self._pending = None

    def fetch(self, max_lines: int = 5000):
        cp = db.get_checkpoint("file_source", {"inode": None, "offset": 0})
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self._pending = None
            return []
        offset = cp.get("offset", 0)
        if cp.get("inode") != st.st_ino or st.st_size < offset:
            offset = 0
        out = []
        with open(self.path, "rb") as fh:
            fh.seek(offset)
            while len(out) < max_lines:
                raw = fh.readline()
                if not raw or not raw.endswith(b"\n"):
                    break
                offset += len(raw)
                line = raw.decode("utf-8", errors="replace").strip()
                rec = _parse(line) if line else None
                if rec:
                    out.append((_uid_for(rec, line), None, rec))
        self._pending = {"inode": st.st_ino, "offset": offset}
        return out

    def commit(self, conn):
        if self._pending:
            db.set_checkpoint(conn, "file_source", self._pending)

    def status(self) -> dict:
        return {"source": "file", "path": self.path, "checkpoint": db.get_checkpoint("file_source")}


class CloudWatchSource:
    """Reads the CloudWatch log group with a saved checkpoint and an overlapping
    window, so retries or delayed delivery never skip or double-count events."""

    name = "cloudwatch"

    def __init__(self):
        import boto3

        self.client = boto3.client("logs", region_name=settings.aws_region)
        self._pending = None
        self.last_error = None

    def fetch(self):
        cp_ms = db.get_checkpoint("cloudwatch_ms")
        now_ms = int(time.time() * 1000)
        if cp_ms is None:
            start = now_ms - settings.cw_initial_lookback_hours * 3600 * 1000
        else:
            start = int(cp_ms) - settings.cw_overlap_seconds * 1000
        kwargs = {"logGroupName": settings.log_group, "startTime": max(0, start), "limit": 10000}
        out, max_ts, pages = [], cp_ms or start, 0
        try:
            while pages < settings.cw_max_pages:
                resp = self.client.filter_log_events(**kwargs)
                pages += 1
                for ev in resp.get("events", []):
                    rec = _parse(ev.get("message", ""))
                    if not rec:
                        continue
                    out.append((_uid_for(rec, ev["eventId"]), ev["eventId"], rec))
                    max_ts = max(max_ts, ev["timestamp"])
                token = resp.get("nextToken")
                if not token:
                    break
                kwargs["nextToken"] = token
            self.last_error = None
        except Exception as exc:
            self.last_error = str(exc)
            log.error("CloudWatch read failed: %s", exc)
            # keep whatever we already read; checkpoint only advances to what we saw
        self._pending = max_ts
        return out

    def commit(self, conn):
        if self._pending is not None:
            db.set_checkpoint(conn, "cloudwatch_ms", int(self._pending))

    def status(self) -> dict:
        return {
            "source": "cloudwatch",
            "log_group": settings.log_group,
            "region": settings.aws_region,
            "checkpoint_ms": db.get_checkpoint("cloudwatch_ms"),
            "last_error": self.last_error,
        }


def make_source():
    if settings.source == "cloudwatch":
        return CloudWatchSource()
    return FileSource(settings.shipped_file)
