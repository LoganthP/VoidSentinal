"""Exercise the deployed protocol without child processes or shared scratch files."""
import io
import json
import zipfile
from dataclasses import replace

import pytest

from test_api import H, cowrie_lines, signed_in
from voidsentinel import auth, db, importer, ml, serverless_import as si


def staged_upload(c, body, name="cowrie.zip"):
    r = c.post("/api/datasets/uploads", json={"filename": name, "size": len(body)}, headers=H)
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    size = r.json()["chunk_bytes"]
    for part, start in enumerate(range(0, len(body), size)):
        r = c.put(f"/api/datasets/uploads/{token}/chunks/{part}", content=body[start:start + size], headers=H)
        assert r.status_code == 200, r.text
    r = c.post(f"/api/datasets/uploads/{token}/complete", headers=H)
    assert r.status_code == 200, r.text
    r = c.post(f"/api/datasets/uploads/{token}/process", headers=H)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "ready", r.text
    return token, r.json()["report"]


def test_durable_zip_analysis_resume_and_model_cold_start(monkeypatch):
    monkeypatch.setattr(importer, "_spawn", lambda *a, **kw: pytest.fail("serverless import spawned a process"))
    monkeypatch.setattr(si, "CHUNK_BYTES", 2048)
    c = signed_in("admin", "admin-pass-123")
    archive = io.BytesIO()
    text = "".join(cowrie_lines(f"durable-{i}", t0=1700000000 + i * 30) for i in range(35))
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("logs/cowrie.json", text)
    token, rep = staged_upload(c, archive.getvalue())
    assert rep["accepted_rows"] == 280
    r = c.post("/api/datasets/import", json={"token": token, "name": "durable-test"}, headers=H)
    assert r.status_code == 200, r.text
    ds = r.json()["id"]
    # Repeating the start request cannot create a second dataset.
    assert c.post("/api/datasets/import", json={"token": token, "name": "retry"}, headers=H).json()["id"] == ds
    r = c.post(f"/api/datasets/{ds}/process", headers=H)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "publishing"
    # Simulate a second instance while another request owns the lease.
    conn = db.get_conn()
    conn.execute("UPDATE import_jobs SET lease='other',lease_until=9999999999 WHERE token=?", (token,))
    conn.commit()
    assert c.post(f"/api/datasets/{ds}/process", headers=H).json()["state"] == "publishing"
    assert conn.execute("SELECT cursor FROM import_jobs WHERE token=?", (token,)).fetchone()[0] == 0
    conn.execute("UPDATE import_jobs SET lease_until=0 WHERE token=?", (token,))
    conn.commit()
    # One request publishes one batch; the next starts from its durable checkpoint.
    ticks = iter([0, 0, 100])
    with monkeypatch.context() as patch:
        patch.setattr(si.time, "monotonic", lambda: next(ticks, 100))
        # Call the worker directly to avoid changing the HTTP client's clock.
        si._publish(si._job(token), conn)
    assert si._job(token)["cursor"] == 1
    assert c.post(f"/api/datasets/{ds}/process", headers=H).json()["state"] == "done"
    d = c.get(f"/api/datasets/{ds}").json()
    assert d["status"] == "ready" and d["events"] == 280 and d["sessions"] == 35
    scope = f"ds:{ds}"
    ov = c.get(f"/api/overview?scope={scope}").json()
    assert ov["sessions"]["total"] == 35
    alerts = c.get(f"/api/alerts?scope={scope}&status=all").json()["items"]
    alert = next(a for a in alerts if a["rule_id"] == "AUTH_BRUTE_SESSION")
    detail = c.get(f"/api/sessions/{alert['session_id']}").json()
    assert sum(bool(e["alert_ids"]) for e in detail["events"]) == 6
    assert "secret" not in json.dumps(detail)
    model = conn.execute("SELECT version FROM models WHERE scope=?", (scope,)).fetchone()[0]
    ml._cache.pop(scope, None)
    conn.execute("UPDATE models SET path='missing-on-this-instance.joblib' WHERE version=?", (model,))
    conn.commit()
    status = c.get(f"/api/ml/status?scope={scope}").json()
    assert status["active_version"] == model and status["scored_sessions"] == 35
    assert conn.execute("SELECT COUNT(*) FROM import_parts WHERE token=?", (token,)).fetchone()[0] == 0
    assert c.delete(f"/api/datasets/{ds}", headers=H).status_code == 200
    assert conn.execute("SELECT 1 FROM model_files WHERE version=?", (model,)).fetchone() is None


def test_chunk_integrity_missing_parts_and_permissions(monkeypatch):
    monkeypatch.setattr(si, "CHUNK_BYTES", 4)
    c = signed_in("admin", "admin-pass-123")
    token = c.post("/api/datasets/uploads", json={"filename": "test.json", "size": 6}, headers=H).json()["token"]
    path = f"/api/datasets/uploads/{token}"
    assert c.post(path + "/complete", headers=H).status_code == 409
    assert c.put(path + "/chunks/0", content=b"abcde", headers=H).status_code == 413
    assert c.put(path + "/chunks/0", content=b"abc", headers=H).status_code == 400
    assert c.put(path + "/chunks/-1", content=b"abcd", headers=H).status_code == 400
    for _ in range(2):
        assert c.put(path + "/chunks/0", content=b"abcd", headers=H).status_code == 200
    assert c.put(path + "/chunks/0", content=b"xxxx", headers=H).status_code == 409
    assert c.put(path + "/chunks/1", content=b"ef", headers=H).status_code == 200
    assert c.post(path + "/complete", headers=H).status_code == 200
    assert c.put(path + "/chunks/0", content=b"abcd", headers=H).status_code == 409
    analyst = signed_in("analyst", "analyst-pass-123")
    assert analyst.post(path + "/process", headers=H).status_code == 403
    assert c.post(path + "/process").status_code == 403


def test_durable_csv_recheck():
    c = signed_in("admin", "admin-pass-123")
    body = b"custom_event,custom_session,custom_time\nlogin.failed,s,1700000000\n"
    token, rep = staged_upload(c, body, "mapped.csv")
    assert rep["accepted_rows"] == 0
    mapping = {"eventid": "custom_event", "session": "custom_session", "timestamp": "custom_time"}
    assert c.post("/api/datasets/recheck", json={"token": token, "mapping": mapping}, headers=H).status_code == 200
    r = c.post(f"/api/datasets/uploads/{token}/process", headers=H)
    assert r.status_code == 200, r.text
    assert r.json()["report"]["accepted_rows"] == 1


def test_admin_password_recovery_applies_once(monkeypatch):
    conn = db.get_conn()
    conn.execute("INSERT INTO users(username,pw_hash,role,created_at) VALUES(?,?,'admin',0)",
                 ("recovery-test", auth.hash_password("old-password-123")))
    conn.commit()
    monkeypatch.setattr(auth, "settings", replace(auth.settings, admin_username="recovery-test",
                        admin_password="recovered-password-123", admin_password_reset_version="test-recovery-v1"))
    auth.seed_users()
    assert auth.verify_password("recovered-password-123", conn.execute("SELECT pw_hash FROM users WHERE username='recovery-test'").fetchone()[0])
    conn.execute("UPDATE users SET pw_hash=? WHERE username='recovery-test'", (auth.hash_password("later-password-123"),))
    conn.commit()
    auth.seed_users()
    assert auth.verify_password("later-password-123", conn.execute("SELECT pw_hash FROM users WHERE username='recovery-test'").fetchone()[0])
