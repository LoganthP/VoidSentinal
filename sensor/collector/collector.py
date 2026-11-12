"""
VoidSentinel sensor collector.

Tails Cowrie's JSON log, sanitizes every record (see sanitize.py), and ships it
to a sink:

  SINK=cloudwatch  -> CloudWatch Logs (put_log_events) — the cloud deployment
  SINK=file        -> an append-only JSONL file      — the local lab

Guarantees
- The read offset is only advanced after the sink confirms the batch, so a
  crash or network failure re-sends instead of losing events.
- Every record carries a deterministic `vs_uid` (hash of sensor + raw line),
  so re-sent records are de-duplicated by the analysis worker.
- A heartbeat record is emitted every HEARTBEAT_SECONDS so the dashboard can
  tell "no attackers right now" apart from "collector is down".

Configuration is entirely through environment variables (see README).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

from sanitize import sanitize

COLLECTOR_VERSION = "1.0.0"

COWRIE_LOG = os.environ.get("COWRIE_LOG", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
SINK = os.environ.get("SINK", "file").lower()
SINK_FILE = os.environ.get("SINK_FILE", "/shipped/events.jsonl")
SENSOR_NAME = os.environ.get("SENSOR_NAME", "lab-sensor")
STATE_FILE = os.environ.get("STATE_FILE", "/state/collector_state.json")
LOG_GROUP = os.environ.get("LOG_GROUP", "/voidsentinel/sensors")
LOG_STREAM = os.environ.get("LOG_STREAM", SENSOR_NAME)
AWS_REGION = os.environ.get("AWS_REGION", "ap-south-1")
HEARTBEAT_SECONDS = int(os.environ.get("HEARTBEAT_SECONDS", "60"))
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "1.0"))
BATCH_MAX = int(os.environ.get("BATCH_MAX", "500"))

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s collector %(levelname)s %(message)s",
)
log = logging.getLogger("collector")
_running = True


def _stop(*_):
    global _running
    _running = False


signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --------------------------------------------------------------------------- state
def load_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"inode": None, "offset": 0, "shipped_total": 0}


def save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, STATE_FILE)


# --------------------------------------------------------------------------- sinks
class FileSink:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def send(self, records: list[dict]) -> None:
        if not records:
            return
        with open(self.path, "a", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())


class CloudWatchSink:
    MAX_BYTES = 900_000  # stay under the 1 MiB request cap

    def __init__(self):
        import boto3  # imported lazily so the lab image doesn't need AWS
        from botocore.exceptions import ClientError

        self.ClientError = ClientError
        self.client = boto3.client("logs", region_name=AWS_REGION)
        self._ensure_stream()

    def _ensure_stream(self):
        try:
            self.client.create_log_stream(logGroupName=LOG_GROUP, logStreamName=LOG_STREAM)
            log.info("created log stream %s/%s", LOG_GROUP, LOG_STREAM)
        except self.ClientError as exc:
            code = exc.response["Error"]["Code"]
            # Terraform pre-creates the stream; the sensor role may not be allowed to create it.
            if code not in ("ResourceAlreadyExistsException", "AccessDeniedException"):
                raise

    def send(self, records: list[dict]) -> None:
        if not records:
            return
        # CloudWatch timestamp = ship time. The original event time stays inside
        # the message. This lets the worker checkpoint on ingestion order, so
        # events shipped late (after an outage) are never skipped.
        now_ms = int(time.time() * 1000)
        batch, size = [], 0
        for rec in records:
            msg = json.dumps(rec, separators=(",", ":"))
            ev_size = len(msg.encode("utf-8")) + 26
            if batch and (size + ev_size > self.MAX_BYTES or len(batch) >= 9_000):
                self._put(batch)
                batch, size = [], 0
            batch.append({"timestamp": now_ms, "message": msg})
            size += ev_size
        if batch:
            self._put(batch)

    def _put(self, events: list[dict]) -> None:
        resp = self.client.put_log_events(
            logGroupName=LOG_GROUP, logStreamName=LOG_STREAM, logEvents=events
        )
        rejected = resp.get("rejectedLogEventsInfo")
        if rejected:
            log.warning("CloudWatch rejected some events: %s", rejected)


def make_sink():
    if SINK == "cloudwatch":
        return CloudWatchSink()
    if SINK == "file":
        return FileSink(SINK_FILE)
    raise SystemExit(f"Unknown SINK={SINK!r}; use 'file' or 'cloudwatch'")


# --------------------------------------------------------------------------- tailing
def read_new_lines(state: dict) -> tuple[list[str], int, int | None]:
    """Return complete new lines, the offset after them, and the file inode."""
    try:
        st = os.stat(COWRIE_LOG)
    except FileNotFoundError:
        return [], state.get("offset", 0), state.get("inode")

    offset = state.get("offset", 0)
    if state.get("inode") != st.st_ino or st.st_size < offset:
        # New file (Cowrie rotates cowrie.json daily) or truncation: start over.
        if state.get("inode") is not None:
            log.info("log rotated or truncated; reading %s from the start", COWRIE_LOG)
        offset = 0

    lines: list[str] = []
    with open(COWRIE_LOG, "rb") as fh:
        fh.seek(offset)
        while len(lines) < BATCH_MAX:
            raw = fh.readline()
            if not raw or not raw.endswith(b"\n"):
                break  # partial line: wait for Cowrie to finish writing it
            offset += len(raw)
            line = raw.decode("utf-8", errors="replace").strip()
            if line:
                lines.append(line)
    return lines, offset, st.st_ino


def to_record(line: str) -> dict | None:
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        log.warning("skipping non-JSON line (%d bytes)", len(line))
        return None
    if not isinstance(raw, dict) or "eventid" not in raw:
        return None
    raw["sensor"] = SENSOR_NAME  # authoritative sensor name from the deployment
    rec = sanitize(raw)
    rec["vs_uid"] = hashlib.sha256(f"{SENSOR_NAME}|{line}".encode()).hexdigest()[:32]
    return rec


def heartbeat(state: dict) -> dict:
    try:
        st = os.stat(COWRIE_LOG)
        size, age = st.st_size, max(0.0, time.time() - st.st_mtime)
    except FileNotFoundError:
        size, age = -1, -1.0
    ts = utc_now_iso()
    return {
        "eventid": "voidsentinel.heartbeat",
        "timestamp": ts,
        "sensor": SENSOR_NAME,
        "shipped_total": state.get("shipped_total", 0),
        "cowrie_log_size": size,
        "cowrie_log_age_s": round(age, 1),
        "collector_version": COLLECTOR_VERSION,
        "vs_uid": hashlib.sha256(f"{SENSOR_NAME}|hb|{ts}".encode()).hexdigest()[:32],
    }


def main() -> int:
    log.info("starting: sink=%s sensor=%s cowrie_log=%s", SINK, SENSOR_NAME, COWRIE_LOG)
    sink = make_sink()
    state = load_state()
    last_hb = 0.0
    backoff = 1.0

    while _running:
        try:
            lines, new_offset, inode = read_new_lines(state)
            records = [r for r in (to_record(l) for l in lines) if r]

            if time.time() - last_hb >= HEARTBEAT_SECONDS:
                records.append(heartbeat(state))
                last_hb = time.time()

            if records:
                sink.send(records)
                shipped = sum(1 for r in records if r["eventid"] != "voidsentinel.heartbeat")
                state.update(inode=inode, offset=new_offset,
                             shipped_total=state.get("shipped_total", 0) + shipped)
                save_state(state)
                if shipped:
                    log.info("shipped %d events (total %d)", shipped, state["shipped_total"])
            elif inode is not None and (inode != state.get("inode") or new_offset != state.get("offset")):
                state.update(inode=inode, offset=new_offset)
                save_state(state)

            backoff = 1.0
            if len(lines) < BATCH_MAX:
                time.sleep(POLL_SECONDS)
        except Exception as exc:  # network/API failures: retry without advancing offset
            log.error("ship failed, retrying in %.0fs: %s", backoff, exc)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)

    log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
