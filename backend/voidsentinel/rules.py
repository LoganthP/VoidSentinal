"""Detection rules.

Every finding carries: a human-readable reason, the exact event IDs that
triggered it (evidence), and a severity. Alerts are idempotent: re-running a
rule over the same session updates the existing alert instead of adding one.
"""
from __future__ import annotations

import json
import sqlite3
import time

from .categories import categorize
from .config import settings
from .sessions import load_session_events

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _finding(rule_id, title, severity, reason, evs):
    return {
        "rule_id": rule_id, "title": title, "severity": severity, "reason": reason,
        "evidence": [e["_uid"] for e in evs][:60],
        "first_ts": min(e["_ts"] for e in evs), "last_ts": max(e["_ts"] for e in evs),
    }


def _commands(events):
    out = []
    for e in events:
        if e["eventid"] == "cowrie.command.input":
            out.append((e, categorize(e.get("input", ""))))
    return out


def session_findings(events: list[dict]) -> list[dict]:
    findings = []
    failed = [e for e in events if e["eventid"] == "cowrie.login.failed"]
    success = [e for e in events if e["eventid"] == "cowrie.login.success"]
    cmds = _commands(events)
    downloads = [e for e in events if e["eventid"] == "cowrie.session.file_download" and e.get("url")]
    chpasswd = [e for e in events if e["eventid"] == "cowrie.command.chpasswd"]

    th = settings.brute_session_threshold
    if len(failed) >= th:
        users = sorted({str(e.get("username")) for e in failed})
        span = failed[-1]["_ts"] - failed[0]["_ts"]
        findings.append(_finding(
            "AUTH_BRUTE_SESSION", "Password guessing in one connection", "medium",
            f"{len(failed)} failed logins in a single session over {span:.0f}s "
            f"(threshold {th}); usernames tried: {', '.join(users[:8])}"
            + (" …" if len(users) > 8 else ""),
            failed,
        ))

    if success and cmds:
        first_cmd = cmds[0][0]
        findings.append(_finding(
            "INTERACTIVE_ACCESS", "Login followed by shell commands", "low",
            f"Logged in as '{success[0].get('username')}' and ran {len(cmds)} command(s); "
            f"first command {first_cmd['_ts'] - success[0]['_ts']:.1f}s after login",
            [success[0]] + [c[0] for c in cmds[:20]],
        ))

    dl_cmds = [e for e, c in cmds if "download" in c]
    if dl_cmds or downloads:
        evs = dl_cmds + downloads
        urls = sorted({e.get("url") for e in downloads if e.get("url")})
        reason = f"{len(dl_cmds)} download command(s)"
        if downloads:
            reason += f", {len(downloads)} file transfer event(s)"
        if urls:
            reason += f"; URLs: {', '.join(urls[:3])}"
        findings.append(_finding("PAYLOAD_DOWNLOAD", "Download attempt in the emulated shell", "high", reason, evs))

    # download followed later by execution = classic dropper behaviour
    if dl_cmds or downloads:
        first_dl = min(e["_ts"] for e in dl_cmds + downloads)
        execs = [e for e, c in cmds if "execution" in c and e["_ts"] >= first_dl]
        if execs:
            findings.append(_finding(
                "DROPPER_CHAIN", "Download followed by execution attempt", "critical",
                f"A download command was followed by {len(execs)} execution command(s) within "
                f"{execs[-1]['_ts'] - first_dl:.0f}s in the emulated shell (dropper pattern; nothing actually ran)",
                (dl_cmds + downloads)[:5] + execs[:10],
            ))

    for cat, rule_id, title, sev in (
        ("persistence", "PERSISTENCE", "Persistence attempt", "high"),
        ("account", "ACCOUNT_TAMPERING", "Account or password change", "high"),
        ("mining", "MINER_INDICATOR", "Crypto-miner indicators", "high"),
        ("evasion", "DEFENSE_EVASION", "History or log tampering", "medium"),
    ):
        hits = [e for e, c in cmds if cat in c]
        if cat == "account":
            hits += chpasswd
        if hits:
            sample = "; ".join((h.get("input") or f"password change for {h.get('username')}")[:60] for h in hits[:2])
            findings.append(_finding(rule_id, title, sev,
                                     f"{len(hits)} command(s) matched '{cat}': {sample}", hits))

    recon = [e for e, c in cmds if "recon" in c]
    if len(recon) >= settings.recon_threshold:
        findings.append(_finding(
            "RECON_BURST", "System reconnaissance", "low",
            f"{len(recon)} reconnaissance commands (threshold {settings.recon_threshold}), "
            "e.g. host, CPU, user and network discovery", recon,
        ))
    return findings


def _upsert_alert(conn, key, f, sensor, session_id, src_ip, related, dataset_id=None) -> int:
    now = time.time()
    alert_id = conn.execute(
        """INSERT INTO alerts(alert_key, rule_id, title, severity, severity_rank, sensor, session_id,
               related_sessions, src_ip, reason, evidence, first_ts, last_ts, created_at, updated_at, dataset_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(alert_key) DO UPDATE SET
               severity=excluded.severity, severity_rank=excluded.severity_rank,
               reason=excluded.reason, evidence=excluded.evidence,
               related_sessions=excluded.related_sessions,
               first_ts=MIN(alerts.first_ts, excluded.first_ts),
               last_ts=MAX(alerts.last_ts, excluded.last_ts), updated_at=excluded.updated_at
           RETURNING id""",
        (key, f["rule_id"], f["title"], f["severity"], SEVERITY_RANK[f["severity"]], sensor,
         session_id, json.dumps(related[:50]), src_ip, f["reason"], json.dumps(f["evidence"]),
         f["first_ts"], f["last_ts"], now, now, dataset_id),
    ).fetchone()[0]
    conn.executemany("INSERT OR IGNORE INTO alert_sessions(alert_id, session_id) VALUES (?, ?)",
                     [(alert_id, sid) for sid in related])
    return alert_id


def refresh_session_stats(conn, session_id: int) -> None:
    conn.execute(
        """UPDATE sessions SET
             alert_count = (SELECT COUNT(*) FROM alert_sessions m WHERE m.session_id = sessions.id),
             max_severity = COALESCE((SELECT MAX(a.severity_rank) FROM alert_sessions m
                                      JOIN alerts a ON a.id = m.alert_id WHERE m.session_id = sessions.id), 0)
           WHERE id = ?""",
        (session_id,),
    )


def run_session_rules(conn: sqlite3.Connection, session_id: int, events: list[dict] | None = None) -> int:
    row = conn.execute("SELECT sensor, session, src_ip, dataset_id FROM sessions WHERE id=?",
                       (session_id,)).fetchone()
    if not row:
        return 0
    if events is None:
        events = load_session_events(conn, row["sensor"], row["session"])
    findings = session_findings(events)
    for f in findings:
        key = f"{f['rule_id']}:{row['sensor']}:{row['session']}"
        _upsert_alert(conn, key, f, row["sensor"], session_id, row["src_ip"], [session_id], row["dataset_id"])
    refresh_session_stats(conn, session_id)
    return len(findings)


def _bursts(rows, window: float):
    """Split time-ordered failures into bursts: a new burst starts after a quiet gap > window."""
    burst = []
    for r in rows:
        if burst and r["ts"] - burst[-1]["ts"] > window:
            yield burst
            burst = []
        burst.append(r)
    if burst:
        yield burst


def run_source_rule(conn: sqlite3.Connection, src_ip: str, dataset_id: int | None = None,
                    lookback: float | None = 86400) -> int:
    """Repeated failed logins from one source spread across several connections (live path)."""
    scope = "dataset_id = ?" if dataset_id is not None else "dataset_id IS NULL"
    sargs = [dataset_id] if dataset_id is not None else []
    q = (f"SELECT event_uid, ts, sensor, session FROM events WHERE {scope} "
         f"AND eventid='cowrie.login.failed' AND src_ip=?")
    args: list = [*sargs, src_ip]
    if lookback is not None:
        latest = conn.execute(f"SELECT MAX(ts) t FROM events WHERE {scope} AND eventid='cowrie.login.failed' "
                              f"AND src_ip=?", args).fetchone()["t"]
        if latest is None:
            return 0
        q += " AND ts >= ?"
        args.append(latest - lookback)
    rows = conn.execute(q + " ORDER BY ts", args).fetchall()
    return emit_source_bursts(conn, src_ip, rows, dataset_id)


def emit_source_bursts(conn, src_ip: str, rows, dataset_id: int | None) -> int:
    """rows: time-ordered failed logins (event_uid, ts, sensor, session) for one source."""
    window, th = settings.brute_source_window, settings.brute_source_threshold
    if len(rows) < th:
        return 0
    created = 0
    for burst in _bursts(rows, window):
        sess_keys = {(r["sensor"], r["session"]) for r in burst}
        if len(burst) < th or len(sess_keys) < 2:
            continue
        ids = []
        for sensor, sess in sess_keys:
            r = conn.execute("SELECT id FROM sessions WHERE sensor=? AND session=?", (sensor, sess)).fetchone()
            if r:
                ids.append(r[0])
        ids.sort()
        n = len(burst)
        span = burst[-1]["ts"] - burst[0]["ts"]
        f = {
            "rule_id": "AUTH_BRUTE_SOURCE", "title": "Repeated login failures across connections",
            "severity": "high" if n >= 5 * th else "medium",
            "reason": f"{n} failed logins from {src_ip} across {len(sess_keys)} connections over {span:.0f}s, "
                      f"with no pause longer than {window}s (threshold {th} failures, ≥2 connections)",
            "evidence": [r["event_uid"] for r in burst][:60],
            "first_ts": burst[0]["ts"], "last_ts": burst[-1]["ts"],
        }
        scope = "dataset_id = ?" if dataset_id is not None else "dataset_id IS NULL"
        # the same burst seen again (sliding live window, re-runs) updates its existing alert
        existing = conn.execute(
            f"SELECT alert_key FROM alerts WHERE rule_id='AUTH_BRUTE_SOURCE' AND src_ip=? AND {scope} "
            f"AND last_ts >= ? AND first_ts <= ? ORDER BY first_ts LIMIT 1",
            (src_ip, *([dataset_id] if dataset_id is not None else []), burst[0]["ts"] - window, burst[-1]["ts"]),
        ).fetchone()
        tag = f"ds{dataset_id}" if dataset_id is not None else "live"
        key = existing[0] if existing else f"AUTH_BRUTE_SOURCE:{tag}:{src_ip}:{int(burst[0]['ts'])}"
        _upsert_alert(conn, key, f, burst[-1]["sensor"], ids[-1] if ids else None, src_ip, ids, dataset_id)
        for sid in ids:
            refresh_session_stats(conn, sid)
        created += 1
    return created
