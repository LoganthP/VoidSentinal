"""Runtime configuration, read once from environment variables."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _cidrs(raw: str) -> list:
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return nets


@dataclass(frozen=True)
class Settings:
    data_dir: str = os.environ.get("VS_DATA_DIR", "/data")
    source: str = os.environ.get("VS_SOURCE", "file").lower()          # file | cloudwatch
    shipped_file: str = os.environ.get("VS_SHIPPED_FILE", "/shipped/events.jsonl")
    aws_region: str = os.environ.get("AWS_REGION", "ap-south-1")
    log_group: str = os.environ.get("VS_LOG_GROUP", "/voidsentinel/sensors")
    cw_overlap_seconds: int = int(os.environ.get("VS_CW_OVERLAP_SECONDS", "600"))
    cw_initial_lookback_hours: int = int(os.environ.get("VS_CW_INITIAL_LOOKBACK_HOURS", "24"))
    cw_max_pages: int = int(os.environ.get("VS_CW_MAX_PAGES", "20"))
    poll_seconds: float = float(os.environ.get("VS_POLL_SECONDS", "5"))
    session_idle_timeout: int = int(os.environ.get("VS_SESSION_IDLE_TIMEOUT", "3600"))
    heartbeat_stale_seconds: int = int(os.environ.get("VS_HEARTBEAT_STALE_SECONDS", "180"))
    # rules
    brute_session_threshold: int = int(os.environ.get("VS_BRUTE_SESSION_THRESHOLD", "5"))
    brute_source_threshold: int = int(os.environ.get("VS_BRUTE_SOURCE_THRESHOLD", "10"))
    brute_source_window: int = int(os.environ.get("VS_BRUTE_SOURCE_WINDOW_SECONDS", "600"))
    recon_threshold: int = int(os.environ.get("VS_RECON_THRESHOLD", "3"))
    # ML
    ml_min_train: int = int(os.environ.get("VS_ML_MIN_TRAIN", "30"))
    ml_retrain_seconds: int = int(os.environ.get("VS_ML_RETRAIN_SECONDS", "21600"))
    ml_retrain_growth: float = float(os.environ.get("VS_ML_RETRAIN_GROWTH", "0.25"))
    ml_include_demo: bool = _bool("VS_ML_INCLUDE_DEMO", False)
    # controlled test traffic is tagged demo and kept out of evaluation
    demo_cidrs: list = field(default_factory=lambda: _cidrs(os.environ.get("VS_DEMO_SOURCE_CIDRS", "")))
    # analyst sign-in (server-side sessions in an HttpOnly cookie)
    session_hours: float = float(os.environ.get("VS_SESSION_HOURS", "8"))        # absolute lifetime
    session_idle_minutes: float = float(os.environ.get("VS_SESSION_IDLE_MINUTES", "120"))
    cookie_secure: str = os.environ.get("VS_COOKIE_SECURE", "auto").lower()      # auto | true | false
    admin_username: str = os.environ.get("VS_ADMIN_USERNAME", "admin").strip()
    admin_password: str = os.environ.get("VS_ADMIN_PASSWORD", "")
    analyst_username: str = os.environ.get("VS_ANALYST_USERNAME", "analyst").strip()
    analyst_password: str = os.environ.get("VS_ANALYST_PASSWORD", "")
    max_upload_mb: int = int(os.environ.get("VS_MAX_UPLOAD_MB", "1024"))

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "voidsentinel.db")

    @property
    def model_dir(self) -> str:
        return os.path.join(self.data_dir, "models")

    def is_demo_ip(self, ip: str | None) -> bool:
        if not ip or not self.demo_cidrs:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.demo_cidrs)


settings = Settings()
