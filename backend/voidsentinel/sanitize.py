"""
VoidSentinel sanitizer.

Runs on the sensor BEFORE any record leaves it. Only allowlisted Cowrie fields
are exported. Captured passwords, Cowrie's free-text `message` field (which
embeds passwords, e.g. "login attempt [root/123456] failed"), raw terminal
recordings (ttylog) and raw forwarded payloads are always dropped.

Command text is redacted (obvious secrets, long encoded blobs) and truncated.
The same module is vendored into the backend as a second line of defence.
"""
from __future__ import annotations

import re

SANITIZER_VERSION = "1"

# Fields we are willing to export. Anything else is dropped.
ALLOWED_FIELDS = {
    "eventid",
    "timestamp",
    "session",
    "sensor",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "username",
    "input",
    "duration",     # seconds (Cowrie 2.x)
    "duration_ms",  # milliseconds (Cowrie 3.x)
    "version",      # SSH client version string
    "hassh",        # client fingerprint (hash, not secret)
    "url",          # download attempts
    "shasum",       # hash of downloaded file
    "destfile",     # path written inside the emulated shell
    "realm",
    "filename",
    "size",
    "arch",
    "width",
    "height",
    "kexAlgs",
    "keyAlgs",
    # VoidSentinel-specific fields
    "vs_uid",
    "vs_redacted",
    "vs_sanitizer",
    "shipped_total",
    "cowrie_log_size",
    "cowrie_log_age_s",
    "collector_version",
}

ALWAYS_DROP = {"password", "message", "ttylog", "data", "stdin"}

MAX_INPUT = 300
MAX_SHORT = 120
MAX_URL = 200

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # echo "user:pass" | chpasswd   /   echo -e "pass\npass" | passwd
    (re.compile(r"(echo\s+(?:-e\s+)?)(['\"]?)[^|;'\"]+\2(\s*\|\s*(?:sudo\s+)?(?:chpasswd|passwd))", re.I),
     r"\1<redacted>\3"),
    # key=value or key: value style secrets
    (re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|token|secret|api[_-]?key|access[_-]?key)(\s*[=:]\s*)(\S+)"),
     r"\1\2<redacted>"),
    # mysql -pSECRET / sshpass -p SECRET
    (re.compile(r"(?i)(\bmysql\b[^;|]*?\s-p)(\S+)"), r"\1<redacted>"),
    (re.compile(r"(?i)(\bsshpass\s+-p\s*)(\S+)"), r"\1<redacted>"),
    # long base64 / hex blobs (encoded payloads, keys)
    (re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"), lambda m: f"<base64:{len(m.group(0))}chars>"),
    (re.compile(r"\b[0-9a-fA-F]{64,}\b"), lambda m: f"<hex:{len(m.group(0))}chars>"),
    # ssh public keys being planted (keep the key type, drop the material)
    (re.compile(r"(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+)\s+[A-Za-z0-9+/=<>:]+"), r"\1 <key>"),
]


def _clean_text(value: object, limit: int) -> str:
    text = str(value)
    if not text.isprintable():  # fast path: most fields need no cleaning
        text = _CTRL.sub(" ", text).replace("\t", " ").replace("\n", " ").replace("\r", " ")
    if len(text) > limit:
        text = text[:limit] + "…[truncated]"
    return text


def redact_command(cmd: str) -> tuple[str, bool]:
    original = cmd
    out = _CTRL.sub(" ", cmd)
    for pattern, repl in _PATTERNS:
        out = pattern.sub(repl, out)
    changed = out != _CTRL.sub(" ", original)
    if len(out) > MAX_INPUT:
        out = out[:MAX_INPUT] + "…[truncated]"
        changed = True
    return out, changed


def sanitize(record: dict) -> dict:
    """Return a new dict containing only safe, allowlisted fields."""
    clean: dict = {}
    redacted = False
    for key, value in record.items():
        if key in ALWAYS_DROP or key not in ALLOWED_FIELDS:
            continue
        if value is None:
            continue
        if key == "input":
            value, changed = redact_command(str(value))
            redacted = redacted or changed
        elif key == "url":
            value = _clean_text(value, MAX_URL)
        elif key in ("kexAlgs", "keyAlgs"):
            if isinstance(value, list):
                value = [_clean_text(v, 60) for v in value[:30]]
            else:
                continue
        elif isinstance(value, str):
            value = _clean_text(value, MAX_SHORT)
        elif isinstance(value, (int, float, bool)):
            pass
        else:
            # nested/unknown structure in an allowed field: stringify safely
            value = _clean_text(value, MAX_SHORT)
        clean[key] = value
    if redacted:
        clean["vs_redacted"] = True
    clean["vs_sanitizer"] = SANITIZER_VERSION
    return clean
