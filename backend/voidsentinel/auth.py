"""Analyst sign-in.

- Passwords: scrypt (stdlib), per-user salt, constant-time comparison.
- Sessions: random 256-bit token in an HttpOnly, SameSite=Strict cookie; only
  its SHA-256 is stored server-side, with an absolute expiry and an idle
  timeout. Sign-out deletes the server-side session, so the cookie is dead
  even if someone copied it.
- Cross-site requests: state-changing calls must carry the X-VS-Request
  header, which browsers cannot add cross-site without a CORS preflight
  (CORS is not enabled).
- Roles: analyst (view, investigate, record verdicts) and admin (also import
  datasets, retrain models, manage access). Enforced on the API.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, Response

from . import db
from .config import settings

log = logging.getLogger("vs.auth")
COOKIE = "vs_session"
DEFAULT_DEMO_PASSWORDS = {"Admin#2026-change-me", "Analyst#2026-change-me"}
_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                              dklen=len(base64.b64decode(dk)))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


_DUMMY = hash_password(secrets.token_hex(8))  # equalises timing for unknown usernames


def validate_new_password(pw: str) -> None:
    if len(pw) < 10:
        raise HTTPException(400, "Passwords need at least 10 characters")


def seed_users() -> None:
    """Create the two starting accounts the first time the API runs."""
    conn = db.get_conn()
    if settings.admin_password_reset_version and settings.admin_password:
        # Explicit, one-time recovery via hosting environment. Changing a password
        # later in Access must never be undone by a subsequent cold start.
        key = "admin_password_reset:" + _h(settings.admin_password_reset_version)
        with db.tx(immediate=True):
            if not db.get_checkpoint(key):
                row = conn.execute("SELECT id FROM users WHERE username=?", (settings.admin_username,)).fetchone()
                if row:
                    conn.execute("UPDATE users SET pw_hash=?,role='admin',active=1,requested_role=NULL WHERE id=?",
                                 (hash_password(settings.admin_password), row["id"]))
                    conn.execute("DELETE FROM auth_sessions WHERE user_id=?", (row["id"],))
                    db.set_checkpoint(conn, key, True)
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]:
        return
    created = []
    for username, pw, role in ((settings.admin_username, settings.admin_password, "admin"),
                               (settings.analyst_username, settings.analyst_password, "analyst")):
        generated = not pw
        pw = pw or secrets.token_urlsafe(12)
        row = conn.execute(
            "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?,?,?,?) "
            "ON CONFLICT(username) DO NOTHING RETURNING id",
            (username, hash_password(pw), role, time.time()),
        ).fetchone()
        if row is not None:
            created.append((username, role, pw if generated else None))
    if settings.admin_password_reset_version and settings.admin_password:
        db.set_checkpoint(conn, "admin_password_reset:" + _h(settings.admin_password_reset_version), True)
    conn.commit()
    for username, role, generated in created:
        if generated:
            log.warning("Created %s account '%s' with generated password: %s  (set VS_%s_PASSWORD to choose one)",
                        role, username, generated, role.upper())
        else:
            log.info("Created %s account '%s' from .env", role, username)
    if {settings.admin_password, settings.analyst_password} & DEFAULT_DEMO_PASSWORDS:
        log.warning("Demo passwords from .env.example are in use. Change them before exposing the dashboard.")


# ---- brute-force protection for the sign-in form (per client IP + username)
_fail_lock = threading.Lock()
_failures: dict[tuple[str, str], deque] = defaultdict(deque)
MAX_FAILS, FAIL_WINDOW = 5, 900


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _check_locked(key) -> None:
    now = time.time()
    with _fail_lock:
        q = _failures[key]
        while q and now - q[0] > FAIL_WINDOW:
            q.popleft()
        if len(q) >= MAX_FAILS:
            wait = int(FAIL_WINDOW - (now - q[0])) // 60 + 1
            raise HTTPException(429, f"Too many failed sign-in attempts. Try again in about {wait} minutes.")


def _record_fail(key) -> None:
    with _fail_lock:
        _failures[key].append(time.time())


def _cookie_secure(request: Request) -> bool:
    if settings.cookie_secure in ("true", "1", "yes"):
        return True
    if settings.cookie_secure in ("false", "0", "no"):
        return False
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return proto == "https"


def login(request: Request, response: Response, username: str, password: str) -> dict:
    key = (_client_ip(request), username.lower())
    _check_locked(key)
    conn = db.get_conn()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    ok = verify_password(password, row["pw_hash"] if row else _DUMMY)
    if not row or not ok or not row["active"]:
        _record_fail(key)
        raise HTTPException(401, "Incorrect username or password")
    with _fail_lock:
        _failures.pop(key, None)
    return _start_session(request, response, row)


def _start_session(request: Request, response: Response, row) -> dict:
    conn = db.get_conn()
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn.execute("INSERT INTO auth_sessions(token_hash, user_id, created_at, expires_at, last_seen) VALUES (?,?,?,?,?)",
                 (_h(token), row["id"], now, now + settings.session_hours * 3600, now))
    conn.execute("UPDATE users SET last_login=? WHERE id=?", (now, row["id"]))
    conn.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (now,))
    conn.commit()
    response.set_cookie(COOKIE, token, httponly=True, secure=_cookie_secure(request), samesite="strict",
                        max_age=int(settings.session_hours * 3600), path="/")
    return _user_out(row)


# ---- self-service accounts
_signups: dict[str, deque] = defaultdict(deque)
MAX_SIGNUPS, SIGNUP_WINDOW = 5, 3600


def signup_options() -> dict:
    return {"signup_enabled": settings.signup_enabled,
            "admin_code_configured": bool(settings.admin_signup_code)}


def signup(request: Request, response: Response, username: str, password: str, role: str,
           admin_code: str | None) -> dict:
    """Analysts are created active. Admins need the invite code from .env; without it the person
    gets analyst access and an admin request that an existing admin approves on the Access page."""
    if not settings.signup_enabled:
        raise HTTPException(403, "Creating accounts here is turned off. Ask an admin to add you.")
    ip = _client_ip(request)
    now = time.time()
    with _fail_lock:
        q = _signups[ip]
        while q and now - q[0] > SIGNUP_WINDOW:
            q.popleft()
        if len(q) >= MAX_SIGNUPS:
            raise HTTPException(429, "Too many new accounts from this address. Try again later.")
    validate_new_password(password)
    if password.lower() == username.lower():
        raise HTTPException(400, "The password can't be the same as the username")
    final_role, requested = "analyst", None
    if role == "admin":
        code = (admin_code or "").strip()
        if code:
            key = (ip, "admin-code")
            _check_locked(key)
            if not settings.admin_signup_code or not hmac.compare_digest(code, settings.admin_signup_code):
                _record_fail(key)
                raise HTTPException(403, "That admin invite code is not valid. Leave it empty to request "
                                         "admin access instead.")
            final_role = "admin"
        else:
            requested = "admin"
    conn = db.get_conn()
    if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        raise HTTPException(409, "That username is taken. Sign in instead, or choose another name.")
    conn.execute("INSERT INTO users(username, pw_hash, role, created_at, requested_role, created_via) "
                 "VALUES (?,?,?,?,?,'signup')", (username, hash_password(password), final_role, now, requested))
    conn.commit()
    with _fail_lock:
        _signups[ip].append(now)
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    log.info("self-service account '%s' created as %s%s", username, final_role,
             " (admin access requested)" if requested else "")
    return _start_session(request, response, row)


def logout(request: Request, response: Response) -> None:
    token = request.cookies.get(COOKIE)
    if token:
        conn = db.get_conn()
        conn.execute("DELETE FROM auth_sessions WHERE token_hash=?", (_h(token),))
        conn.commit()
    response.delete_cookie(COOKIE, path="/")


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _user_out(row) -> dict:
    keys = row.keys()
    return {"id": row["id"], "username": row["username"], "role": row["role"],
            "requested_role": row["requested_role"] if "requested_role" in keys else None}


def current_user(request: Request) -> dict:
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-vs-request") != "1":
        raise HTTPException(403, "Missing X-VS-Request header")
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "Sign in to continue")
    conn = db.get_conn()
    row = conn.execute(
        "SELECT s.token_hash, s.expires_at, s.last_seen, u.* FROM auth_sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash=?", (_h(token),)).fetchone()
    now = time.time()
    if (not row or not row["active"] or row["expires_at"] < now
            or now - row["last_seen"] > settings.session_idle_minutes * 60):
        if row:
            conn.execute("DELETE FROM auth_sessions WHERE token_hash=?", (row["token_hash"],))
            conn.commit()
        raise HTTPException(401, "Your session has ended. Sign in again.")
    if now - row["last_seen"] > 60:
        conn.execute("UPDATE auth_sessions SET last_seen=? WHERE token_hash=?", (now, row["token_hash"]))
        conn.commit()
    return _user_out(row)


def require_admin(request: Request) -> dict:
    user = current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Only admins can do this")
    return user


def end_user_sessions(user_id: int) -> None:
    db.get_conn().execute("DELETE FROM auth_sessions WHERE user_id=?", (user_id,))
