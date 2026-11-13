"""Self-service accounts: role rules, invite code, approval, limits."""
import os
import tempfile

os.environ["VS_DATA_DIR"] = os.environ.get("VS_DATA_DIR") or tempfile.mkdtemp()
os.environ.setdefault("VS_ADMIN_PASSWORD", "admin-pass-123")
os.environ.setdefault("VS_ANALYST_PASSWORD", "analyst-pass-123")

from fastapi.testclient import TestClient  # noqa: E402

from voidsentinel import auth, db  # noqa: E402
from voidsentinel.api import app  # noqa: E402
from voidsentinel.config import settings  # noqa: E402

db.init()
auth.seed_users()
H = {"X-VS-Request": "1"}


import contextlib  # noqa: E402


@contextlib.contextmanager
def setting(name, value):
    """Settings is a frozen dataclass; override one value for a test and restore it."""
    old = getattr(settings, name)
    object.__setattr__(settings, name, value)
    try:
        yield
    finally:
        object.__setattr__(settings, name, old)


def fresh():
    auth._signups.clear()
    auth._failures.clear()
    return TestClient(app)


def signup(c, user, role="analyst", code=None, pw="long-enough-pw-1"):
    return c.post("/api/auth/signup", json={"username": user, "password": pw, "role": role, "admin_code": code},
                  headers=H)


def test_analyst_signup_is_active_and_signed_in():
    c = fresh()
    assert c.get("/api/auth/options").json()["signup_enabled"] is True
    r = signup(c, "newanalyst")
    assert r.status_code == 200 and r.json()["role"] == "analyst"
    assert c.get("/api/overview").status_code == 200          # signed in straight away
    assert c.post("/api/ml/retrain", headers=H).status_code == 403  # but not an admin
    assert signup(fresh(), "NewAnalyst").status_code == 409   # usernames are case-insensitive


def test_admin_with_code_and_without():
    with setting("admin_signup_code", "invite-2026"):
        _admin_flow()


def _admin_flow():
    c = fresh()
    assert signup(c, "badcode", "admin", "nope").status_code == 403
    assert db.get_conn().execute("SELECT 1 FROM users WHERE username='badcode'").fetchone() is None
    r = signup(c, "realadmin", "admin", "invite-2026")
    assert r.status_code == 200 and r.json()["role"] == "admin"
    assert c.get("/api/users").status_code == 200

    # no code: analyst access now, admin request waits for approval
    p = fresh()
    r = signup(p, "wantsadmin", "admin")
    assert r.json()["role"] == "analyst" and r.json()["requested_role"] == "admin"
    assert p.get("/api/users").status_code == 403
    users = c.get("/api/users").json()["items"]
    uid = next(u["id"] for u in users if u["username"] == "wantsadmin" and u["requested_role"] == "admin")
    assert c.patch(f"/api/users/{uid}", json={"role": "admin"}, headers=H).status_code == 200
    assert p.get("/api/auth/me").json() is None  # role change signs them out; they sign in again as admin
    r = p.post("/api/auth/login", json={"username": "wantsadmin", "password": "long-enough-pw-1"}, headers=H)
    assert r.json()["role"] == "admin" and r.json()["requested_role"] is None


def test_validation_limits_and_switch():
    c = fresh()
    assert signup(c, "shortpw", pw="short").status_code == 422
    assert signup(c, "samepass12", pw="SamePass12").status_code == 400
    assert signup(c, "bad name!").status_code == 422
    assert c.post("/api/auth/signup", json={"username": "noheader", "password": "long-enough-pw-1"}).status_code == 403
    for i in range(5):
        assert signup(c, f"bulk{i}").status_code == 200
    assert signup(c, "bulk5").status_code == 429
    with setting("signup_enabled", False):
        assert fresh().get("/api/auth/options").json()["signup_enabled"] is False
        assert signup(fresh(), "closed1").status_code == 403
