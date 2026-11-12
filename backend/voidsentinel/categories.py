"""Map shell command text (as typed into Cowrie) to behavior categories.

Categories are deliberately coarse and explainable: each one corresponds to a
question an analyst would ask ("did they try to download something?").
"""
from __future__ import annotations

import re

CATEGORY_LABELS = {
    "recon": "System reconnaissance",
    "download": "Payload download",
    "execution": "Execution",
    "persistence": "Persistence",
    "account": "Account tampering",
    "evasion": "Defense evasion",
    "mining": "Crypto-mining indicators",
    "network": "Network activity",
    "file_ops": "File operations",
    "other": "Other",
}

_RULES: list[tuple[str, re.Pattern]] = [
    ("mining", re.compile(r"xmrig|minerd|cpuminer|stratum\+tcp|cryptonight|nicehash|monero|c3pool|supportxmr", re.I)),
    ("download", re.compile(r"\b(wget|curl|tftp|ftpget|lwp-download|fetch)\b|busybox\s+(wget|tftp)|scp\s|\bgit\s+clone\b", re.I)),
    ("persistence", re.compile(r"crontab|/etc/cron|authorized_keys|rc\.local|/etc/init\.d|systemctl\s+enable|\.bashrc|\.profile|/etc/profile|update-rc\.d", re.I)),
    ("account", re.compile(r"\b(passwd|chpasswd|useradd|usermod|adduser|userdel|groupadd)\b", re.I)),
    ("evasion", re.compile(r"history\s+-c|HISTFILE|\.bash_history|rm\s+-rf\s+/var/log|/var/log/\S*\s*$|setenforce\s+0|ufw\s+disable|iptables\s+-F|unset\s+HIST|chattr\s", re.I)),
    ("execution", re.compile(r"chmod\s+\+?[0-7]*x|chmod\s+7[0-7]{2}|(^|\s|;)\./\S|\bnohup\b|\b(sh|bash|python3?|perl|php)\s+\S+|\bexec\b|\beval\b|\bsetsid\b", re.I)),
    ("recon", re.compile(r"\buname\b|\bwhoami\b|^\s*id\b|/proc/cpuinfo|/proc/meminfo|\bnproc\b|\bfree\b|\blscpu\b|\bifconfig\b|\bip\s+(a|addr|r|route)\b|^\s*w\s*$|\buptime\b|\bhostname\b|\bps\b|\btop\b|\bdf\b|/etc/os-release|/etc/issue|\blspci\b|\bdmidecode\b|\bgetconf\b|/etc/passwd|\blast\b|\bwho\b", re.I)),
    ("network", re.compile(r"\bnetstat\b|\bss\s+-|\bnc\b|\bncat\b|\bping\b|\bnmap\b|\bmasscan\b|\btelnet\b|/dev/tcp/", re.I)),
    ("file_ops", re.compile(r"^\s*(cd|ls|cat|echo|mkdir|rm|cp|mv|touch|head|tail|grep|find|pwd|tar|unzip|gzip)\b", re.I)),
]

_SPLIT = re.compile(r"\s*(?:;|&&|\|\||\|)\s*")


def split_commands(text: str) -> list[str]:
    return [p for p in _SPLIT.split(text or "") if p.strip()]


def categorize(text: str) -> set[str]:
    cats: set[str] = set()
    for part in split_commands(text) or [text or ""]:
        matched = False
        for name, pattern in _RULES:
            if pattern.search(part):
                cats.add(name)
                matched = True
        if not matched and part.strip():
            cats.add("other")
    return cats
