"""Did ML improve triage?

Protocol (reproducible):
1. Split completed, non-demo sessions by start time at `split_ts`.
2. Train a fresh Isolation Forest on sessions before the split only.
3. For every week after the split, each strategy picks `budget` sessions:
     rules_only : sessions with alerts, by max severity, then alert count
     rules_ml   : all sessions, by severity (0-1) + anomaly percentile (0-1)
4. Compare picks against analyst verdicts. Unreviewed picks are reported,
   never assumed good or bad.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime, timezone

from . import ml
from .config import settings


def _fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%d %b %Y %H:%M")


def _week(ts: float) -> str:
    y, w, _ = datetime.fromtimestamp(ts, tz=timezone.utc).isocalendar()
    return f"{y}-W{w:02d}"


def _tally(picks: list[dict]) -> dict:
    out = {"picked": len(picks), "reviewed": 0, "investigate": 0, "routine": 0, "uncertain": 0, "unreviewed": 0}
    for p in picks:
        v = p["verdict"]
        if v in ("investigate", "routine", "uncertain"):
            out["reviewed"] += 1
            out[v] += 1
        else:
            out["unreviewed"] += 1
    out["precision"] = round(out["investigate"] / out["reviewed"], 3) if out["reviewed"] else None
    return out


def _merge(a: dict, b: dict) -> dict:
    keys = ("picked", "reviewed", "investigate", "routine", "uncertain", "unreviewed")
    m = {k: a.get(k, 0) + b.get(k, 0) for k in keys}
    m["precision"] = round(m["investigate"] / m["reviewed"], 3) if m["reviewed"] else None
    return m


def _eligible(conn, scope: str, include_demo: bool) -> tuple[list, bool, bool]:
    is_dataset = scope.startswith("ds:")
    if is_dataset:
        include_demo = True  # imported data has no demo traffic
        q = f"SELECT * FROM sessions WHERE status='closed' AND dataset_id = {int(scope[3:])}"
    else:
        q = "SELECT * FROM sessions WHERE status='closed' AND dataset_id IS NULL"
    if not include_demo:
        q += " AND is_demo=0"
    return conn.execute(q + " ORDER BY start_ts").fetchall(), is_dataset, include_demo


def default_split(rows) -> float | None:
    """Median session, but never fewer than ml_min_train sessions to train on."""
    if len(rows) <= settings.ml_min_train:
        return None
    return rows[max(settings.ml_min_train, len(rows) // 2)]["start_ts"]


def plan(conn, scope: str = "live", include_demo: bool = False, split_ts: float | None = None) -> dict:
    """What a run would use, so the form can show it before the analyst clicks Run (SQL aggregates only)."""
    is_dataset = scope.startswith("ds:")
    base = (f"status='closed' AND dataset_id = {int(scope[3:])}" if is_dataset
            else "status='closed' AND dataset_id IS NULL")
    if not is_dataset and not include_demo:
        base += " AND is_demo=0"
    agg = conn.execute(f"SELECT COUNT(*) n, MIN(start_ts) a, MAX(start_ts) b, SUM(verdict IS NOT NULL) rv "
                       f"FROM sessions WHERE {base}").fetchone()
    n = agg["n"] or 0
    demo_total = 0 if (is_dataset or include_demo) else conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE status='closed' AND dataset_id IS NULL AND is_demo=1").fetchone()[0]
    d_split = None
    if n > settings.ml_min_train:
        d_split = conn.execute(f"SELECT start_ts FROM sessions WHERE {base} ORDER BY start_ts LIMIT 1 OFFSET ?",
                               (max(settings.ml_min_train, n // 2),)).fetchone()[0]
    use = split_ts if split_ts is not None else d_split
    train = test = rt = it = 0
    if use is not None:
        r = conn.execute(f"SELECT SUM(start_ts < ?) tr, SUM(start_ts >= ?) te, "
                         f"SUM(start_ts >= ? AND verdict IS NOT NULL) rt, "
                         f"SUM(start_ts >= ? AND verdict = 'investigate') it FROM sessions WHERE {base}",
                         (use, use, use, use)).fetchone()
        train, test, rt, it = (r["tr"] or 0), (r["te"] or 0), (r["rt"] or 0), (r["it"] or 0)
    return {
        "scope": scope, "include_demo": include_demo and not is_dataset,
        "eligible": n, "demo_excluded": demo_total,
        "first_ts": agg["a"], "last_ts": agg["b"],
        "default_split_ts": d_split, "split_ts": use,
        "train": train, "test": test, "min_train": settings.ml_min_train,
        "reviewed_total": agg["rv"] or 0, "reviewed_test": rt, "investigate_test": it,
        "ready": train >= settings.ml_min_train and test > 0,
    }


def run(conn, budget: int = 20, split_ts: float | None = None, include_demo: bool = False,
        scope: str = "live") -> dict:
    rows, is_dataset, include_demo = _eligible(conn, scope, include_demo)
    if not rows and include_demo:
        return {"ok": False, "error": "No completed sessions yet."}
    if not rows:
        demo = conn.execute("SELECT COUNT(*) c FROM sessions WHERE is_demo=1 AND dataset_id IS NULL").fetchone()["c"]
        why = (f" All {demo} sessions so far come from demo source ranges (VS_DEMO_SOURCE_CIDRS). Tick "
               "'Include demo traffic for a lab check' to test the pipeline, or expose the cloud sensor "
               "to real traffic.") if demo else " Expose the cloud sensor to real traffic and review some sessions first."
        return {"ok": False, "error": "No completed non-demo sessions to evaluate yet." + why}

    if split_ts is None:
        split_ts = default_split(rows)
        if split_ts is None:
            split_ts = rows[-1]["start_ts"] + 1
    train = [r for r in rows if r["start_ts"] < split_ts]
    test = [r for r in rows if r["start_ts"] >= split_ts]
    span = " Pick a split inside the eligible range shown above the form, or clear it to use the default."
    if len(rows) < settings.ml_min_train + 1:
        return {"ok": False, "error": f"Only {len(rows)} completed sessions; the evaluation needs more than "
                                      f"{settings.ml_min_train} (enough to train on, plus some to test)."}
    if len(train) < settings.ml_min_train:
        return {"ok": False,
                "error": f"The training period before the split has {len(train)} sessions; it needs "
                         f"{settings.ml_min_train}." + span}
    if not test:
        return {"ok": False, "error": "No sessions after the split." + span}

    bundle = ml.fit(train)
    items = []
    scored = ml.score_many(bundle, [ml.raw_features(r) for r in test])
    for r, (_, pct, _) in zip(test, scored):
        items.append({
            "id": r["id"], "start_ts": r["start_ts"], "src_ip": r["src_ip"],
            "outcome": r["outcome"], "max_severity": r["max_severity"] or 0,
            "alert_count": r["alert_count"] or 0, "anomaly_pct": pct, "verdict": r["verdict"],
        })

    weeks: dict[str, list] = defaultdict(list)
    for it in items:
        weeks[_week(it["start_ts"])].append(it)

    weekly, tot_r, tot_m = [], {}, {}
    ml_only_hits, ml_only_ids = 0, []
    for wk in sorted(weeks):
        cands = weeks[wk]
        rules_pick = sorted(
            [c for c in cands if c["alert_count"] > 0],
            key=lambda c: (-c["max_severity"], -c["alert_count"], c["start_ts"]),
        )[:budget]
        ml_pick = sorted(
            cands, key=lambda c: (-(c["max_severity"] / 4.0 + c["anomaly_pct"] / 100.0), c["start_ts"])
        )[:budget]
        r_t, m_t = _tally(rules_pick), _tally(ml_pick)
        surfaced = [c for c in ml_pick if c["alert_count"] == 0]
        hits = [c for c in surfaced if c["verdict"] == "investigate"]
        ml_only_hits += len(hits)
        ml_only_ids += [c["id"] for c in hits]
        weekly.append({
            "week": wk, "sessions": len(cands),
            "alerts": sum(1 for c in cands if c["alert_count"] > 0),
            "rules_only": r_t, "rules_ml": m_t,
            "ml_surfaced_without_alert": len(surfaced),
            "ml_only_investigate": len(hits),
        })
        tot_r, tot_m = _merge(tot_r, r_t), _merge(tot_m, m_t)

    total_investigate = sum(1 for it in items if it["verdict"] == "investigate")
    reviewed_total = sum(1 for it in items if it["verdict"])
    scope_cond = f"dataset_id = {int(scope[3:])}" if is_dataset else "dataset_id IS NULL"
    alert_rows = conn.execute(
        f"SELECT COUNT(*) c FROM alerts WHERE first_ts >= ? AND {scope_cond}", (split_ts,)
    ).fetchone()["c"]

    return {
        "ok": True,
        "generated_at": time.time(),
        "protocol": {
            "split_ts": split_ts, "budget_per_week": budget,
            "train_sessions": len(train), "test_sessions": len(test),
            "feature_version": ml.FEATURE_VERSION,
            "train_from": train[0]["start_ts"], "train_to": train[-1]["start_ts"],
            "demo_sessions_excluded": not include_demo,
        },
        "totals": {
            "rules_only": tot_r, "rules_ml": tot_m,
            "ml_only_investigate": ml_only_hits, "ml_only_session_ids": ml_only_ids[:50],
            "alerts_in_test_period": alert_rows,
            "reviewed_test_sessions": reviewed_total,
            "investigate_in_test_period": total_investigate,
            "recall_rules_only": round(tot_r.get("investigate", 0) / total_investigate, 3) if total_investigate else None,
            "recall_rules_ml": round(tot_m.get("investigate", 0) / total_investigate, 3) if total_investigate else None,
        },
        "weekly": weekly,
        "demo_included": include_demo and not is_dataset,
        "scope": scope,
        "caveat": ("Only sessions with analyst verdicts count toward precision and recall. "
                   "Review the unreviewed picks of both strategies for a fair comparison."),
    }
