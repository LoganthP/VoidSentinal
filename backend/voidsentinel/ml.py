"""Anomaly ranking of completed sessions with scikit-learn's Isolation Forest.

The score measures *unusualness relative to previously observed sessions*,
not maliciousness. Each score comes with an explanation: the features that
deviate most from the training baseline (robust z-scores).
"""
from __future__ import annotations

import json
import logging
import math
import os
import sqlite3
import time
import io

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .config import settings
from . import db

log = logging.getLogger("vs.ml")

FEATURE_VERSION = "v1"
FEATURES = [
    # name, human label, transform
    ("duration_s", "Session duration (s)", "log1p"),
    ("failed_logins", "Failed logins", "log1p"),
    ("login_success", "Logged in", "raw"),
    ("command_count", "Commands run", "log1p"),
    ("distinct_categories", "Distinct command categories", "raw"),
    ("time_to_first_command_s", "Time to first command (s)", "log1p"),
    ("mean_event_gap_s", "Mean gap between events (s)", "log1p"),
    ("event_count", "Events in session", "log1p"),
]
FEATURE_NAMES = [f[0] for f in FEATURES]


def raw_features(row: sqlite3.Row | dict) -> dict:
    """Features an analyst can verify directly from the session's events."""
    cats = row["categories"]
    if isinstance(cats, str):
        cats = json.loads(cats or "[]")
    duration = float(row["duration"] or 0.0)
    if row["first_command_ts"] is not None and row["start_ts"] is not None:
        ttfc = max(0.0, float(row["first_command_ts"]) - float(row["start_ts"]))
    else:
        ttfc = duration  # no command ever: "first command" never came within the session
    return {
        "duration_s": round(duration, 3),
        "failed_logins": int(row["login_failed"] or 0),
        "login_success": 1 if (row["login_success"] or 0) > 0 else 0,
        "command_count": int(row["command_count"] or 0),
        "distinct_categories": len([c for c in cats if c != "other"]),
        "time_to_first_command_s": round(ttfc, 3),
        "mean_event_gap_s": round(float(row["mean_gap"] or 0.0), 3),
        "event_count": int(row["event_count"] or 0),
    }


def vectorize(feats: dict) -> list[float]:
    out = []
    for name, _, tf in FEATURES:
        v = float(feats[name])
        out.append(math.log1p(max(v, 0.0)) if tf == "log1p" else v)
    return out


def _scope_where(scope: str) -> tuple[str, list]:
    if scope.startswith("ds:"):
        return "dataset_id = ?", [int(scope[3:])]
    return "dataset_id IS NULL", []


def _training_rows(conn, before_ts: float | None = None, include_demo: bool | None = None, scope: str = "live"):
    include_demo = settings.ml_include_demo if include_demo is None else include_demo
    w, args = _scope_where(scope)
    q = f"SELECT * FROM sessions WHERE status='closed' AND {w}"
    if not include_demo:
        q += " AND is_demo=0"
    if before_ts is not None:
        q += " AND start_ts < ?"
        args.append(before_ts)
    q += " ORDER BY start_ts"
    return conn.execute(q, args).fetchall()


MAX_FIT = 20000  # Isolation Forest subsamples anyway; this bounds memory on big imports


def fit(rows) -> dict:
    if len(rows) > MAX_FIT:
        rng = np.random.default_rng(42)
        idx = np.sort(rng.choice(len(rows), MAX_FIT, replace=False))
        rows = [rows[i] for i in idx]
    raws = [raw_features(r) for r in rows]
    X = np.array([vectorize(f) for f in raws], dtype=float)
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(X)
    train_scores = -model.score_samples(X)  # higher = more unusual
    med = np.median(X, axis=0)
    q75, q25 = np.percentile(X, 75, axis=0), np.percentile(X, 25, axis=0)
    iqr = q75 - q25
    std = X.std(axis=0)
    scale = np.where(iqr > 1e-9, iqr / 1.349, np.where(std > 1e-9, std, 1.0))
    raw_med = {name: float(np.median([f[name] for f in raws])) for name in FEATURE_NAMES}
    return {
        "model": model,
        "train_scores": np.sort(train_scores),
        "median": med, "scale": scale, "raw_median": raw_med,
        "n": len(rows),
    }


def score_many(bundle: dict, feats_list: list[dict]) -> list[tuple[float, float, list[dict]]]:
    if not feats_list:
        return []
    X = np.array([vectorize(f) for f in feats_list], dtype=float)
    raws = -bundle["model"].score_samples(X)
    ts = bundle["train_scores"]
    pcts = np.searchsorted(ts, raws, side="right") / len(ts) * 100.0
    Z = (X - bundle["median"]) / bundle["scale"]
    out = []
    for k, feats in enumerate(feats_list):
        z = Z[k]
        explanation = []
        for i in np.argsort(-np.abs(z))[:3]:
            if abs(z[i]) < 0.5:
                continue
            name, label, _ = FEATURES[i]
            explanation.append({
                "feature": name, "label": label, "value": feats[name],
                "baseline_median": bundle["raw_median"][name],
                "direction": "higher" if z[i] > 0 else "lower", "z": round(float(z[i]), 2),
            })
        out.append((round(float(raws[k]), 4), round(float(pcts[k]), 1), explanation))
    return out


def score(bundle: dict, feats: dict) -> tuple[float, float, list[dict]]:
    return score_many(bundle, [feats])[0]


# ---------------------------------------------------------------- persistence
_cache: dict = {}  # scope -> (version, bundle)


def scope_of(row) -> str:
    return f"ds:{row['dataset_id']}" if row["dataset_id"] is not None else "live"


def active_model(conn, scope: str = "live") -> tuple[str | None, dict | None]:
    row = conn.execute("SELECT version, path FROM models WHERE active=1 AND scope=?", (scope,)).fetchone()
    if not row:
        return None, None
    cached = _cache.get(scope)
    if not cached or cached[0] != row["version"]:
        try:
            _cache[scope] = (row["version"], joblib.load(row["path"]))
        except FileNotFoundError:
            stored = conn.execute("SELECT data FROM model_files WHERE version=?", (row["version"],)).fetchone()
            if not stored:
                return None, None
            _cache[scope] = (row["version"], joblib.load(io.BytesIO(bytes(stored[0]))))
    return _cache[scope]


def train_and_activate(conn, scope: str = "live", commit_chunks: bool = False) -> dict:
    # imported datasets are always third-party traffic, so is_demo is 0 there
    rows = _training_rows(conn, scope=scope)
    if len(rows) < settings.ml_min_train:
        return {"trained": False,
                "reason": f"Need at least {settings.ml_min_train} completed sessions for a baseline "
                          f"(have {len(rows)})."}
    bundle = fit(rows)
    tag = "live" if scope == "live" else scope.replace(":", "")
    version = f"{FEATURE_VERSION}-{tag}-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-n{len(rows)}"
    os.makedirs(settings.model_dir, exist_ok=True)
    path = os.path.join(settings.model_dir, f"{version}.joblib")
    joblib.dump(bundle, path)
    # Models must survive cold starts just like their scores and metadata.
    if not db._isolated.get():
        with open(path, "rb") as model_file:
            conn.execute("INSERT OR REPLACE INTO model_files(version,data) VALUES(?,?)", (version, model_file.read()))
    stats = {"feature_names": FEATURE_NAMES, "raw_median": bundle["raw_median"],
             "include_demo": settings.ml_include_demo if scope == "live" else False}
    conn.execute("UPDATE models SET active=0 WHERE scope=?", (scope,))
    conn.execute(
        "INSERT INTO models(version, created_at, n_train, train_from, train_to, feature_version, path, stats, active, scope) "
        "VALUES (?,?,?,?,?,?,?,?,1,?)",
        (version, time.time(), len(rows), rows[0]["start_ts"], rows[-1]["start_ts"],
         FEATURE_VERSION, path, json.dumps(stats), scope),
    )
    _cache[scope] = (version, bundle)
    n = rescore_all(conn, scope, commit_chunks=commit_chunks)
    log.info("trained model %s on %d sessions, rescored %d", version, len(rows), n)
    return {"trained": True, "version": version, "n_train": len(rows), "rescored": n}


def _write_scores(conn, rows, version, bundle) -> int:
    feats = [raw_features(r) for r in rows]
    if bundle is None:
        conn.executemany("UPDATE sessions SET features=? WHERE id=?",
                         [(json.dumps(f), r["id"]) for f, r in zip(feats, rows)])
        return 0
    scored = score_many(bundle, feats)
    conn.executemany(
        "UPDATE sessions SET features=?, anomaly_score=?, anomaly_pct=?, model_version=?, explanation=? WHERE id=?",
        [(json.dumps(f), raw, pct, version, json.dumps(expl), r["id"])
         for f, r, (raw, pct, expl) in zip(feats, rows, scored)],
    )
    return len(rows)


def score_session(conn, session_id: int) -> bool:
    row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not row or row["status"] != "closed":
        return False
    version, bundle = active_model(conn, scope_of(row))
    return _write_scores(conn, [row], version, bundle) > 0


def rescore_all(conn, scope: str = "live", chunk: int = 5000, commit_chunks: bool = False) -> int:
    version, bundle = active_model(conn, scope)
    w, args = _scope_where(scope)
    total, last_id = 0, 0
    while True:
        rows = conn.execute(f"SELECT * FROM sessions WHERE status='closed' AND {w} AND id > ? ORDER BY id LIMIT ?",
                            (*args, last_id, chunk)).fetchall()
        if not rows:
            return total
        total += _write_scores(conn, rows, version, bundle)
        last_id = rows[-1]["id"]
        if commit_chunks:
            conn.commit()  # short write transactions keep the dashboard and live worker responsive


def maybe_retrain(conn) -> dict | None:
    """Live sensor data only; imported datasets are trained once, at import."""
    n_now = len(_training_rows(conn))
    row = conn.execute("SELECT created_at, n_train FROM models WHERE active=1 AND scope='live'").fetchone()
    if row is None:
        if n_now >= settings.ml_min_train:
            return train_and_activate(conn)
        return None
    grew = n_now >= row["n_train"] * (1 + settings.ml_retrain_growth)
    aged = time.time() - row["created_at"] >= settings.ml_retrain_seconds and n_now > row["n_train"]
    if grew or aged:
        return train_and_activate(conn)
    return None


def status(conn, scope: str = "live") -> dict:
    version, _ = active_model(conn, scope)
    row = conn.execute("SELECT * FROM models WHERE active=1 AND scope=?", (scope,)).fetchone()
    w0, a0 = _scope_where(scope)
    demo = "" if (scope != "live" or settings.ml_include_demo) else " AND is_demo=0"
    eligible = conn.execute(f"SELECT COUNT(*) FROM sessions WHERE status='closed' AND {w0}{demo}", a0).fetchone()[0]
    w, args = _scope_where(scope)
    scored = conn.execute(f"SELECT COUNT(*) c FROM sessions WHERE anomaly_score IS NOT NULL AND {w}",
                          args).fetchone()["c"]
    return {
        "scope": scope,
        "active_version": version,
        "trained_at": row["created_at"] if row else None,
        "n_train": row["n_train"] if row else 0,
        "feature_version": FEATURE_VERSION,
        "features": [{"name": n, "label": l} for n, l, _ in FEATURES],
        "eligible_sessions": eligible,
        "min_train": settings.ml_min_train,
        "include_demo": settings.ml_include_demo if scope == "live" else False,
        "scored_sessions": scored,
        "history": [dict(r) for r in conn.execute(
            "SELECT version, created_at, n_train, active FROM models WHERE scope=? ORDER BY created_at DESC LIMIT 10",
            (scope,))],
    }
