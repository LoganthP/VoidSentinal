"""Ingestion worker — the single writer for events, sessions and alerts.

    python -m voidsentinel.worker            # run forever
    python -m voidsentinel.worker --once     # one pass (useful for tests/cron)
"""
from __future__ import annotations

import argparse
import logging
import signal
import time

from . import db, ml, rules
from .config import settings
from .sessions import HEARTBEAT, close_idle_sessions, rebuild_session, store_event, update_sensor
from .sources import make_source

log = logging.getLogger("vs.worker")
_running = True


def _stop(*_):
    global _running
    _running = False


def process_batch(conn, batch) -> dict:
    touched_sessions: set[tuple[str, str]] = set()
    touched_ips: set[str] = set()
    new = 0
    for uid, cw_id, rec in batch:
        if not store_event(conn, uid, cw_id, rec):
            continue  # duplicate (overlap window / retry) — ignored
        new += 1
        update_sensor(conn, rec)
        if rec["eventid"] == HEARTBEAT or not rec.get("session"):
            continue
        touched_sessions.add((rec.get("sensor") or "unknown", rec["session"]))
        if rec["eventid"] == "cowrie.login.failed" and rec.get("src_ip"):
            touched_ips.add(rec["src_ip"])

    alerts = 0
    for sensor, session in touched_sessions:
        sid = rebuild_session(conn, sensor, session)
        if sid is None:
            continue
        alerts += rules.run_session_rules(conn, sid)
        ml.score_session(conn, sid)  # no-op for open sessions
    for ip in touched_ips:
        alerts += rules.run_source_rule(conn, ip, dataset_id=None)
    return {"received": len(batch), "new": new, "sessions": len(touched_sessions), "findings": alerts}


def run_once(source) -> int:
    batch = source.fetch()
    with db.tx() as conn:
        stats = process_batch(conn, batch)
        source.commit(conn)
        for sid in close_idle_sessions(conn):
            ml.score_session(conn, sid)
        result = ml.maybe_retrain(conn)
        db.set_checkpoint(conn, "worker_status", {
            "last_pass_ts": time.time(), "last_new": stats["new"], **source.status(),
        })
    if stats["new"]:
        log.info("ingested %(new)d new / %(received)d read, %(sessions)d sessions, %(findings)d findings", stats)
    if result and result.get("trained"):
        log.info("model %s active (n=%s)", result["version"], result["n_train"])
    return stats["new"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level="INFO", format="%(asctime)s %(name)s %(levelname)s %(message)s")
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    db.init()
    source = make_source()
    log.info("worker started: source=%s db=%s", source.name, settings.db_path)
    if args.once:
        run_once(source)
        return
    while _running:
        try:
            n = run_once(source)
        except Exception:
            log.exception("worker pass failed; retrying")
            n = 0
        if n == 0:
            for _ in range(int(settings.poll_seconds * 10)):
                if not _running:
                    break
                time.sleep(0.1)
    log.info("worker stopped")


if __name__ == "__main__":
    main()
