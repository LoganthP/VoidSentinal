"""API tests: sign-in, roles, upload → preview → import → analysis.

    cd backend && python -m pytest -q
"""
import json
import os
import tempfile
import time

os.environ["VS_DATA_DIR"] = tempfile.mkdtemp()
os.environ["VS_ADMIN_PASSWORD"] = "admin-pass-123"
os.environ["VS_ANALYST_PASSWORD"] = "analyst-pass-123"

from fastapi.testclient import TestClient  # noqa: E402

from voidsentinel import auth, db  # noqa: E402
from voidsentinel.api import app  # noqa: E402

db.init()
auth.seed_users()

H = {"X-VS-Request": "1"}


def client():
    return TestClient(app)


def signed_in(user, pw):
    c = client()
    r = c.post("/api/auth/login", json={"username": user, "password": pw}, headers=H)
    assert r.status_code == 200, r.text
    assert "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()
    return c


def cowrie_lines(sess="s1", ip="203.0.113.7", fails=6, t0=1700000000):
    ev = [{"eventid": "cowrie.session.connect", "session": sess, "src_ip": ip, "timestamp": t0, "protocol": "ssh"}]
    for i in range(fails):
        ev.append({"eventid": "cowrie.login.failed", "session": sess, "src_ip": ip, "timestamp": t0 + 1 + i,
                   "username": "root", "password": f"secret{i}",
                   "message": f"login attempt [root/secret{i}] failed"})
    ev.append({"eventid": "cowrie.session.closed", "session": sess, "src_ip": ip, "timestamp": t0 + 20,
               "duration": "20.0"})
    return "\n".join(json.dumps(e) for e in ev) + "\n"


def upload(c, name, body: bytes):
    """Upload, then poll the background validation until it finishes."""
    r = c.post(f"/api/datasets/upload?filename={name}", content=body, headers=H)
    assert r.status_code == 200, r.text
    return wait_validation(c, r.json()["token"])


def wait_validation(c, token):
    for _ in range(300):
        st = c.get(f"/api/datasets/uploads/{token}").json()
        if st["state"] != "validating":
            assert st["state"] == "ready", st
            return token, st["report"]
        time.sleep(0.1)
    raise AssertionError("validation did not finish")


def wait_ready(c, ds_id):
    for _ in range(300):
        d = c.get(f"/api/datasets/{ds_id}").json()
        if d["status"] != "importing":
            return d
        time.sleep(0.1)
    raise AssertionError("import did not finish")


def test_auth_required_and_roles():
    with client() as c:
        assert c.get("/api/overview").status_code == 401
        assert c.post("/api/auth/login", json={"username": "admin", "password": "wrong-pass"}, headers=H).status_code == 401
        assert c.post("/api/auth/login", json={"username": "admin", "password": "admin-pass-123"}).status_code == 403  # no header
    a = signed_in("analyst", "analyst-pass-123")
    assert a.get("/api/auth/me").json()["role"] == "analyst"
    assert a.get("/api/overview").status_code == 200
    assert a.post("/api/datasets/upload?filename=x.jsonl", content=b"{}", headers=H).status_code == 403
    assert a.post("/api/ml/retrain", headers=H).status_code == 403
    assert a.get("/api/users").status_code == 403
    a.post("/api/auth/logout", headers=H)
    assert a.get("/api/overview").status_code == 401
    assert a.get("/api/auth/me").json() is None


def test_logout_kills_copied_cookie():
    a = signed_in("analyst", "analyst-pass-123")
    stolen = dict(a.cookies)
    a.post("/api/auth/logout", headers=H)
    c = client()
    c.cookies.update(stolen)
    assert c.get("/api/auth/me").json() is None and c.get("/api/overview").status_code == 401


def test_import_flow_and_analysis():
    adm = signed_in("admin", "admin-pass-123")
    body = (cowrie_lines("aa11", "203.0.113.7") + cowrie_lines("bb22", "203.0.113.7", t0=1700000030)
            + "not json\n").encode()
    token, rep = upload(adm, "small.jsonl", body)
    assert rep["accepted_rows"] == 16 and rep["rejected_rows"] == 1 and rep["sessions"] == 2
    assert rep["stripped"]["password_fields"] == 12
    r = adm.post("/api/datasets/import", json={"token": token, "name": "small"}, headers=H)
    assert r.status_code == 200, r.text
    ds = wait_ready(adm, r.json()["id"])
    assert ds["status"] == "ready" and ds["sessions"] == 2 and "Anomaly ranking skipped" in ds["stage"]
    scope = f"ds:{ds['id']}"
    ov = adm.get(f"/api/overview?scope={scope}").json()
    assert ov["sessions"]["total"] == 2 and ov["events"]["failed"] == 12
    assert adm.get("/api/overview?scope=live").json()["sessions"]["total"] == 0  # live untouched
    alerts = adm.get(f"/api/alerts?scope={scope}&status=all").json()["items"]
    rules = {a["rule_id"] for a in alerts}
    assert {"AUTH_BRUTE_SESSION", "AUTH_BRUTE_SOURCE"} <= rules
    sid = next(a["session_id"] for a in alerts if a["rule_id"] == "AUTH_BRUTE_SESSION")
    detail = adm.get(f"/api/sessions/{sid}").json()
    assert detail["provenance"]["kind"] == "dataset"
    assert sum(1 for e in detail["events"] if e["alert_ids"]) == 6
    assert "secret" not in json.dumps(detail)
    # analyst records a verdict -> alert moves to Triaged and keeps who decided
    an = signed_in("analyst", "analyst-pass-123")
    v = an.post(f"/api/sessions/{sid}/verdict", json={"verdict": "investigate", "note": "brute force"}, headers=H).json()
    assert v["verdict_by"] == "analyst" and v["alerts_updated"] >= 1
    tri = an.get(f"/api/alerts?scope={scope}&status=triaged").json()
    assert any(a["session_id"] == sid for a in tri["items"])


def test_csv_with_mapping_and_prefix_repair():
    adm = signed_in("admin", "admin-pass-123")
    csv_text = "Event Type,Session ID,Time,Source IP,user,pass\n" + "".join(
        f"login.failed,cc33,2024-03-01 10:00:{i:02d},198.51.100.9,root,pw{i}\n" for i in range(6))
    token, rep = upload(adm, "export.csv", csv_text.encode())
    assert rep["format"] == "csv"
    mapping = {"eventid": "Event Type", "session": "Session ID", "timestamp": "Time", "src_ip": "Source IP",
               "username": "user"}
    r = adm.post("/api/datasets/recheck", json={"token": token, "mapping": mapping}, headers=H)
    _, rep = wait_validation(adm, r.json()["token"])
    assert rep["accepted_rows"] == 6 and rep["prefixed_eventids"] == 6 and rep["stripped"]["password_fields"] == 6
    assert "pw1" not in json.dumps(rep)


def test_zero_valid_rows_is_a_clear_error():
    adm = signed_in("admin", "admin-pass-123")
    token, rep = upload(adm, "bad.jsonl", b'{"hello": 1}\nnope\n')
    assert rep["accepted_rows"] == 0 and rep["problem"]
    r2 = adm.post("/api/datasets/import", json={"token": token, "name": "bad"}, headers=H)
    assert r2.status_code == 400
    assert adm.post("/api/datasets/upload?filename=empty.jsonl", content=b"", headers=H).status_code == 400


def test_overview_for_dataset_is_precomputed_and_large_import_is_not_blocking():
    adm = signed_in("admin", "admin-pass-123")
    body = "".join(cowrie_lines(f"z{i:03d}", f"192.0.2.{i % 50 + 1}", fails=3, t0=1700100000 + i * 30)
                   for i in range(400)).encode()
    token, rep = upload(adm, "many.jsonl", body)
    assert rep["sessions"] == 400
    ds = adm.post("/api/datasets/import", json={"token": token, "name": "many"}, headers=H).json()
    # the API answers while the import runs in its own process
    t = time.time()
    assert adm.get("/api/overview").status_code == 200 and time.time() - t < 2
    token2, _ = upload(adm, "again.jsonl", cowrie_lines("q1"))
    second = adm.post("/api/datasets/import", json={"token": token2, "name": "again"}, headers=H)
    d = wait_ready(adm, ds["id"])
    assert d["status"] == "ready" and d["sessions"] == 400
    assert second.status_code in (200, 409)  # 409 if the first import was still running
    ov = adm.get(f"/api/overview?scope=ds:{ds['id']}").json()
    assert ov["sessions"]["total"] == 400 and ov["events"]["failed"] == 1200
    assert ov["top_sources"] and ov["series"]["points"]
    assert adm.get(f"/api/ml/status?scope=ds:{ds['id']}").json()["active_version"]
