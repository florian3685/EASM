#!/usr/bin/env python3
"""
link-ed.it CyberScan - Internal Web Console
===========================================
Small standard-library web app for authorized customer-domain security scans.

Start:
    python web_app.py --host 0.0.0.0 --port 18080

Optional environment variables:
    EASM_WEB_USERS       Comma-separated users, e.g. "alice:secret,bob:secret"
    EASM_WEB_USERS_FILE  Persistent user store path (default: web_users.json)
    EASM_WEB_TOKEN       Fallback shared token when EASM_WEB_USERS is not set
    EASM_WEB_MAX_WORKERS Number of concurrent background scans (default: 1)
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import html
import hmac
import json
import mimetypes
import os
import re
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import config
from checkpoint import Checkpoint
from html_report import calculate_risk_score, extract_findings
from main import MODULE_REGISTRY, RESULT_KEYS, run_module
from report import ReportGenerator
from state_manager import StateTracker


BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"
APP_TITLE = "link-ed.it CyberScan"
APP_TAGLINE = "Internal customer-domain security scans"
COMPANY_NAME = "link-ed.it"
USERS_FILE = Path(os.environ.get("EASM_WEB_USERS_FILE", str(BASE_DIR / "web_users.json")))
WEB_TOKEN = os.environ.get("EASM_WEB_TOKEN", "").strip()
WEB_USERS_RAW = os.environ.get("EASM_WEB_USERS", "").strip()
SESSION_COOKIE = "easm_session"
SESSION_TTL_SECONDS = int(os.environ.get("EASM_WEB_SESSION_SECONDS", "43200"))
SESSION_SECRET = (
    os.environ.get("EASM_WEB_SESSION_SECRET")
    or WEB_TOKEN
    or secrets.token_hex(32)
).encode("utf-8")
DEFAULT_WEB_PORT = int(os.environ.get("EASM_WEB_PORT", "18080"))
MAX_WORKERS = int(os.environ.get("EASM_WEB_MAX_WORKERS", "1"))
USER_ROLES = [
    {"id": "admin", "label": "Admin"},
    {"id": "scanner", "label": "Scanner"},
    {"id": "viewer", "label": "Viewer"},
]
ROLE_IDS = {role["id"] for role in USER_ROLES}
USER_LOCK = threading.RLock()
ENV_FILE = BASE_DIR / ".env"

API_KEY_FIELDS = [
    {
        "env": "VT_API_KEY",
        "config_key": "virustotal",
        "label": "VirusTotal",
        "description": "Domain/IP reputation lookups and malware intelligence.",
    },
    {
        "env": "HIBP_API_KEY",
        "config_key": "hibp",
        "label": "Have I Been Pwned",
        "description": "Breach lookups for customer-domain email exposure.",
    },
    {
        "env": "ABUSEIPDB_API_KEY",
        "config_key": "abuseipdb",
        "label": "AbuseIPDB",
        "description": "Abuse confidence and IP reputation checks.",
    },
    {
        "env": "GSB_API_KEY",
        "config_key": "google_safebrowsing",
        "label": "Google Safe Browsing",
        "description": "Phishing and malware reputation checks.",
    },
    {
        "env": "SHODAN_API_KEY",
        "config_key": "shodan",
        "label": "Shodan",
        "description": "Passive exposure, banner and CVE enrichment.",
    },
    {
        "env": "GITHUB_TOKEN",
        "config_key": "github",
        "label": "GitHub Token",
        "description": "GitHub code search for domain-related leaks.",
    },
    {
        "env": "EASM_WEBHOOK_URL",
        "config_key": None,
        "label": "Alert Webhook",
        "description": "Optional Slack/Discord webhook for scan-diff notifications.",
    },
]
API_KEY_ENVS = {field["env"] for field in API_KEY_FIELDS}

DEFAULT_MODULES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14]
MODULE_DESCRIPTIONS = {
    1: "Hosts, ports, CVEs, login portals",
    2: "TLS, headers, CDN/WAF signals",
    3: "DNSSEC, CAA, AXFR, WHOIS",
    4: "SPF, DKIM, DMARC, mail TLS",
    5: "Trackers, cookies, Safe Browsing",
    6: "Breaches, LeakIX, OSINT signals",
    7: "Wayback, endpoints, recon extras",
    8: "Hidden parameter discovery",
    9: "GitHub code and token hunting",
    10: "S3, Azure, GCP bucket checks",
    11: "Active exploitation",
    12: "Dangling DNS and takeover checks",
    13: "JavaScript secret scanning",
    14: "API, admin and exposed asset mapping",
}

PROFILES = [
    {
        "id": "full_recon",
        "name": "Full Recon",
        "modules": DEFAULT_MODULES,
        "exploit": False,
    },
    {
        "id": "quick_wins",
        "name": "Quick Wins",
        "modules": [1, 12, 13, 14],
        "exploit": False,
    },
    {
        "id": "osint_only",
        "name": "OSINT Only",
        "modules": [5, 6, 9],
        "exploit": False,
    },
    {
        "id": "cloud_source",
        "name": "Cloud & Source",
        "modules": [9, 10, 12, 13, 14],
        "exploit": False,
    },
    {
        "id": "mail_dns",
        "name": "Mail & DNS",
        "modules": [1, 3, 4],
        "exploit": False,
    },
    {
        "id": "full_assault",
        "name": "Authorized Active Test",
        "modules": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
        "exploit": True,
    },
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_domain(value: str) -> str:
    domain = (value or "").strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
    if "/" in domain:
        domain = domain.split("/", 1)[0]
    if ":" in domain:
        domain = domain.split(":", 1)[0]
    return domain


def validate_domain(value: str) -> str:
    domain = normalize_domain(value)
    if not domain:
        raise ValueError("Target domain is required.")
    if len(domain) > 253:
        raise ValueError("Target domain is too long.")
    if not re.fullmatch(r"[a-z0-9.-]+", domain):
        raise ValueError("Use a hostname like example.com.")
    if "." not in domain:
        raise ValueError("Use a fully qualified domain like example.com.")
    if domain.startswith(".") or domain.endswith(".") or ".." in domain:
        raise ValueError("Use a valid domain name.")
    return domain


def parse_modules(raw_modules: Any) -> list[int]:
    if raw_modules is None:
        return DEFAULT_MODULES[:]
    if not isinstance(raw_modules, list):
        raise ValueError("Modules must be a list.")
    modules = sorted({int(item) for item in raw_modules})
    if not modules:
        raise ValueError("Select at least one module.")
    invalid = [m for m in modules if m not in MODULE_REGISTRY]
    if invalid:
        raise ValueError(f"Invalid module selection: {invalid}")
    return modules


def mask_secret(value: str) -> str:
    value = value or ""
    if not value:
        return ""
    if len(value) <= 8:
        return "configured"
    return f"{value[:4]}...{value[-4:]}"


def quote_env_value(value: str) -> str:
    escaped = (value or "").replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def api_key_current_value(field: dict[str, Any]) -> str:
    env_name = str(field["env"])
    config_key = field.get("config_key")
    if config_key:
        return str(config.API_KEYS.get(str(config_key), "") or "")
    if env_name == "EASM_WEBHOOK_URL":
        return str(getattr(config, "WEBHOOK_URL", "") or os.environ.get(env_name, "") or "")
    return str(os.environ.get(env_name, "") or "")


def list_api_key_status() -> list[dict[str, Any]]:
    rows = []
    for field in API_KEY_FIELDS:
        value = api_key_current_value(field)
        rows.append({
            "env": field["env"],
            "label": field["label"],
            "description": field["description"],
            "configured": bool(value),
            "masked": mask_secret(value),
        })
    return rows


def write_env_values(changes: dict[str, str]) -> None:
    existing_lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    pending = {key: value for key, value in changes.items() if key in API_KEY_ENVS}
    written: set[str] = set()
    output: list[str] = []

    for line in existing_lines:
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if match and match.group(1) in pending:
            key = match.group(1)
            output.append(f"{key}={quote_env_value(pending[key])}")
            written.add(key)
        else:
            output.append(line)

    if pending.keys() - written:
        if output and output[-1].strip():
            output.append("")
        output.append("# link-ed.it CyberScan API keys")
        for key in sorted(pending.keys() - written):
            output.append(f"{key}={quote_env_value(pending[key])}")

    tmp_path = ENV_FILE.with_suffix(".env.tmp")
    tmp_path.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    os.replace(tmp_path, ENV_FILE)
    try:
        os.chmod(ENV_FILE, 0o600)
    except OSError:
        pass


def update_api_keys(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_values = payload.get("values", {})
    clear_values = set(payload.get("clear", []) or [])
    if not isinstance(raw_values, dict):
        raise ValueError("values must be an object.")

    changes: dict[str, str] = {}
    for env_name, value in raw_values.items():
        env_name = str(env_name)
        if env_name not in API_KEY_ENVS:
            continue
        value = str(value or "").strip()
        if value:
            changes[env_name] = value

    for env_name in clear_values:
        env_name = str(env_name)
        if env_name in API_KEY_ENVS:
            changes[env_name] = ""

    if not changes:
        return list_api_key_status()

    write_env_values(changes)
    for field in API_KEY_FIELDS:
        env_name = str(field["env"])
        if env_name not in changes:
            continue
        value = changes[env_name]
        os.environ[env_name] = value
        config_key = field.get("config_key")
        if config_key:
            config.API_KEYS[str(config_key)] = value
        elif env_name == "EASM_WEBHOOK_URL":
            config.WEBHOOK_URL = value
    return list_api_key_status()


def parse_web_users(raw: str) -> dict[str, str]:
    """Parse EASM_WEB_USERS from JSON or comma-separated user:password pairs."""
    if not raw:
        return {}
    if raw.lstrip().startswith("{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("EASM_WEB_USERS JSON is invalid.") from exc
        if not isinstance(data, dict):
            raise ValueError("EASM_WEB_USERS JSON must be an object.")
        return {str(user).strip(): str(password) for user, password in data.items() if str(user).strip()}

    users: dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            raise ValueError("EASM_WEB_USERS entries must look like user:password.")
        username, password = entry.split(":", 1)
        username = username.strip()
        if username:
            users[username] = password
    return users


def normalize_role(value: str) -> str:
    role = (value or "").strip().lower()
    return role if role in ROLE_IDS else "scanner"


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    rounds = 200_000
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("ascii"),
        rounds,
    ).hex()
    return f"pbkdf2_sha256${rounds}${salt}${digest}"


def password_matches(stored: str, supplied: str) -> bool:
    """Support pbkdf2_sha256, sha256$hex and plain values."""
    stored = stored or ""
    supplied = supplied or ""
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, rounds_raw, salt, expected = stored.split("$", 3)
            rounds = int(rounds_raw)
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                supplied.encode("utf-8"),
                salt.encode("ascii"),
                rounds,
            ).hex()
            return secrets.compare_digest(expected, digest)
        except (ValueError, TypeError):
            return False
    if stored.startswith("sha256$"):
        digest = hashlib.sha256(supplied.encode("utf-8")).hexdigest()
        return secrets.compare_digest(stored.removeprefix("sha256$"), digest)
    return secrets.compare_digest(stored, supplied)


def _empty_user_store() -> dict[str, Any]:
    return {"users": {}}


def load_user_store() -> dict[str, Any]:
    with USER_LOCK:
        if not USERS_FILE.exists():
            return _empty_user_store()
        try:
            with USERS_FILE.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return _empty_user_store()
        users = data.get("users")
        if not isinstance(users, dict):
            return _empty_user_store()
        return {"users": users}


def save_user_store(data: dict[str, Any]) -> None:
    with USER_LOCK:
        USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = USERS_FILE.with_suffix(USERS_FILE.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
        os.replace(tmp_path, USERS_FILE)
        try:
            os.chmod(USERS_FILE, 0o600)
        except OSError:
            pass


def bootstrap_managed_users(seed_users: dict[str, str]) -> None:
    if USERS_FILE.exists() or not seed_users:
        return
    data = _empty_user_store()
    for index, (username, stored_password) in enumerate(seed_users.items()):
        password_value = (
            stored_password
            if stored_password.startswith(("pbkdf2_sha256$", "sha256$"))
            else hash_password(stored_password)
        )
        data["users"][username] = {
            "username": username,
            "password": password_value,
            "role": "admin" if index == 0 else "scanner",
            "active": True,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "source": "env-seed",
        }
    save_user_store(data)


def has_managed_users() -> bool:
    return bool(load_user_store().get("users"))


def get_managed_user(username: str) -> dict[str, Any] | None:
    user = load_user_store().get("users", {}).get((username or "").strip())
    return user if isinstance(user, dict) else None


def sanitize_user(username: str, user: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": username,
        "role": normalize_role(str(user.get("role", "scanner"))),
        "active": bool(user.get("active", True)),
        "created_at": user.get("created_at", ""),
        "updated_at": user.get("updated_at", ""),
        "source": user.get("source", "local"),
    }


def list_managed_users() -> list[dict[str, Any]]:
    users = load_user_store().get("users", {})
    return [
        sanitize_user(username, user)
        for username, user in sorted(users.items(), key=lambda item: item[0].lower())
        if isinstance(user, dict)
    ]


def _active_admin_count(data: dict[str, Any]) -> int:
    count = 0
    for user in data.get("users", {}).values():
        if not isinstance(user, dict):
            continue
        if user.get("active", True) and normalize_role(str(user.get("role"))) == "admin":
            count += 1
    return count


def upsert_managed_user(
    username: str,
    password: str,
    role: str,
    active: bool,
    updated_by: str,
) -> dict[str, Any]:
    username = (username or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._@-]{2,64}", username):
        raise ValueError("Use 2-64 characters for usernames: letters, numbers, dot, dash, underscore or @.")

    data = load_user_store()
    users = data.setdefault("users", {})
    existing = users.get(username)
    now = utc_now()
    first_user = not users
    final_role = "admin" if first_user else normalize_role(role)
    password = password or ""

    if existing and not isinstance(existing, dict):
        existing = None
    if not existing and len(password) < 8:
        raise ValueError("New users need a password with at least 8 characters.")
    if password and len(password) < 8:
        raise ValueError("Passwords need at least 8 characters.")

    record = {
        "username": username,
        "password": existing.get("password") if existing else hash_password(password),
        "role": final_role,
        "active": bool(active),
        "created_at": existing.get("created_at", now) if existing else now,
        "updated_at": now,
        "updated_by": updated_by,
        "source": "local",
    }
    if password:
        record["password"] = hash_password(password)

    users[username] = record
    if _active_admin_count(data) < 1:
        raise ValueError("At least one active admin user is required.")
    save_user_store(data)
    return sanitize_user(username, record)


def delete_managed_user(username: str) -> None:
    username = (username or "").strip()
    data = load_user_store()
    users = data.get("users", {})
    if username not in users:
        raise ValueError("User not found.")
    removed = users.pop(username)
    if isinstance(removed, dict) and _active_admin_count(data) < 1:
        users[username] = removed
        raise ValueError("At least one active admin user is required.")
    save_user_store(data)


WEB_USERS = parse_web_users(WEB_USERS_RAW)
bootstrap_managed_users(WEB_USERS)


def setup_required() -> bool:
    return not has_managed_users() and not WEB_USERS and not WEB_TOKEN


def auth_required() -> bool:
    return True


def auth_mode() -> str:
    if setup_required():
        return "setup"
    if has_managed_users():
        return "managed"
    if WEB_USERS:
        return "users"
    if WEB_TOKEN:
        return "token"
    return "managed"


def verify_login(username: str, password: str) -> str | None:
    username = (username or "").strip()
    password = password or ""
    if setup_required():
        return None
    managed = get_managed_user(username)
    if managed:
        if managed.get("active", True) and password_matches(str(managed.get("password", "")), password):
            return username
        return None
    if has_managed_users():
        return None
    if WEB_USERS:
        stored = WEB_USERS.get(username)
        if stored is not None and password_matches(stored, password):
            return username
        return None
    if WEB_TOKEN and secrets.compare_digest(password, WEB_TOKEN):
        return username or "team"
    if not auth_required():
        return username or "local"
    return None


def user_role(username: str | None) -> str:
    username = username or ""
    if setup_required():
        return "viewer"
    managed = get_managed_user(username)
    if has_managed_users():
        if managed and managed.get("active", True):
            return normalize_role(str(managed.get("role", "scanner")))
        return "viewer"
    if username in WEB_USERS:
        return "admin"
    if username in {"team", "local"} and WEB_TOKEN:
        return "admin"
    return "viewer"


def is_admin_user(username: str | None) -> bool:
    return user_role(username) == "admin"


def can_start_scan(username: str | None) -> bool:
    return user_role(username) in {"admin", "scanner"}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def sign_session(username: str) -> str:
    payload = {
        "user": username,
        "exp": int(time.time()) + SESSION_TTL_SECONDS,
    }
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(SESSION_SECRET, payload_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_b64}.{b64url(sig)}"


def verify_session(value: str) -> str | None:
    if not value or "." not in value:
        return None
    payload_b64, sig_b64 = value.rsplit(".", 1)
    expected = b64url(hmac.new(SESSION_SECRET, payload_b64.encode("ascii"), hashlib.sha256).digest())
    if not secrets.compare_digest(sig_b64, expected):
        return None
    try:
        payload = json.loads(b64url_decode(payload_b64).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    username = str(payload.get("user", "")).strip()
    return username or None


def public_path(path: Path) -> str:
    rel = path.resolve().relative_to(RESULTS_DIR.resolve())
    return "/reports/" + "/".join(rel.parts)


def safe_report_path(url_path: str) -> Path:
    rel = unquote(url_path.removeprefix("/reports/"))
    if not rel or rel.startswith("/"):
        raise FileNotFoundError
    candidate = (RESULTS_DIR / rel).resolve()
    if RESULTS_DIR.resolve() not in candidate.parents:
        raise FileNotFoundError
    if candidate.suffix.lower() not in {".html", ".json", ".pdf"}:
        raise FileNotFoundError
    if not candidate.is_file():
        raise FileNotFoundError
    return candidate


def load_report_summary(path: Path) -> dict[str, Any]:
    stat = path.stat()
    summary: dict[str, Any] = {
        "domain": path.parent.name,
        "file": path.name,
        "type": path.suffix.lower().lstrip("."),
        "size": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "url": public_path(path),
    }
    if path.suffix.lower() == ".json":
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            findings = extract_findings(data)
            score, label = calculate_risk_score(findings)
            summary.update(
                {
                    "scan_date": (data.get("meta") or {}).get("scan_date", ""),
                    "risk_score": score,
                    "risk_label": label,
                    "findings": len(findings),
                }
            )
        except Exception as exc:
            summary["error"] = str(exc)
    return summary


def list_reports() -> list[dict[str, Any]]:
    if not RESULTS_DIR.exists():
        return []
    reports: list[dict[str, Any]] = []
    for path in RESULTS_DIR.glob("*/*"):
        if path.is_file() and path.suffix.lower() in {".json", ".html", ".pdf"}:
            reports.append(load_report_summary(path))
    return sorted(reports, key=lambda item: item.get("modified", ""), reverse=True)


@dataclass
class ScanJob:
    id: str
    domain: str
    modules: list[int]
    stealth: bool
    exploit: bool
    fresh: bool
    authorized: bool
    created_by: str
    status: str = "queued"
    progress: int = 0
    current_module: int | None = None
    phase: str = "Waiting"
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    generated_files: list[str] = field(default_factory=list)
    error: str | None = None
    logs: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.logs.append(f"[{stamp}] {message}")
            self.logs = self.logs[-160:]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "domain": self.domain,
                "modules": self.modules,
                "stealth": self.stealth,
                "exploit": self.exploit,
                "fresh": self.fresh,
                "authorized": self.authorized,
                "created_by": self.created_by,
                "status": self.status,
                "progress": self.progress,
                "current_module": self.current_module,
                "phase": self.phase,
                "created_at": self.created_at,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "generated_files": self.generated_files,
                "error": self.error,
                "logs": self.logs[-80:],
            }


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def create(
        self,
        domain: str,
        modules: list[int],
        stealth: bool,
        exploit: bool,
        fresh: bool,
        authorized: bool,
        created_by: str,
    ) -> ScanJob:
        job = ScanJob(
            id=secrets.token_hex(8),
            domain=domain,
            modules=modules,
            stealth=stealth,
            exploit=exploit,
            fresh=fresh,
            authorized=authorized,
            created_by=created_by,
        )
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = list(self._jobs.values())
        return sorted(
            (job.snapshot() for job in jobs),
            key=lambda item: item.get("created_at", ""),
            reverse=True,
        )


JOBS = JobStore()
EXECUTOR = ThreadPoolExecutor(max_workers=max(1, MAX_WORKERS))


def run_scan_job(job: ScanJob) -> None:
    with job._lock:
        job.status = "running"
        job.started_at = utc_now()
        job.phase = "Preparing scan"
    job.log(f"Scan started for {job.domain} by {job.created_by}.")

    old_stealth = config.STEALTH_MODE
    config.STEALTH_MODE = job.stealth

    try:
        if not job.authorized:
            raise ValueError("Customer authorization must be confirmed before scanning.")
        if 11 in job.modules and not job.exploit:
            raise ValueError("Module 11 requires explicit exploit mode.")
        if job.exploit and 11 not in job.modules:
            job.modules = sorted(set(job.modules + [11]))

        cp = Checkpoint(job.domain, str(RESULTS_DIR))
        results: dict[str, Any] = {}
        completed: list[int] = []

        if job.fresh and cp.exists():
            cp.clear()
            job.log("Existing checkpoint removed.")
        elif cp.exists():
            snapshot = cp.load()
            if snapshot:
                results = snapshot.get("results", {}) or {}
                completed = snapshot.get("_meta", {}).get("completed_modules", []) or []
                job.log(f"Resuming checkpoint with {len(completed)} completed module(s).")

        total = len(job.modules)
        for index, module_num in enumerate(job.modules, start=1):
            name = MODULE_REGISTRY[module_num][0]
            result_key = RESULT_KEYS[module_num]

            if module_num in completed:
                job.log(f"Skipped module {module_num}: {name} already completed.")
                with job._lock:
                    job.progress = int(index / total * 90)
                continue

            with job._lock:
                job.current_module = module_num
                job.phase = f"Module {module_num}: {name}"
                job.progress = int((index - 1) / total * 90)
            job.log(f"Running module {module_num}: {name}")

            def on_progress(partial: dict[str, Any], hint: str, key: str = result_key) -> None:
                results[key] = partial
                cp.save(results, completed, current_module=module_num, phase=hint)
                with job._lock:
                    job.phase = f"Module {module_num}: {name} ({hint})"
                job.log(f"Progress in module {module_num}: {hint}")

            results[result_key] = run_module(module_num, job.domain, results, on_progress=on_progress)
            completed.append(module_num)
            cp.save(results, completed, current_module=None)
            job.log(f"Completed module {module_num}: {name}")

        with job._lock:
            job.phase = "Generating reports"
            job.progress = 92
        generator = ReportGenerator(job.domain, results)
        generated = [Path(generator.generate_json(str(RESULTS_DIR)))]
        try:
            generated.append(Path(generator.generate_html(str(RESULTS_DIR))))
        except Exception as exc:
            job.log(f"HTML report failed: {exc}")
        try:
            generated.append(Path(generator.generate_pdf(str(RESULTS_DIR))))
        except Exception as exc:
            job.log(f"PDF report failed: {exc}")

        with job._lock:
            job.phase = "Updating scan history"
            job.progress = 96
        try:
            tracker = StateTracker(str(BASE_DIR / "easm_state.db"))
            tracker.handle_diffing(job.domain, results)
        except Exception as exc:
            job.log(f"State tracking failed: {exc}")

        cp.clear()
        with job._lock:
            job.generated_files = [public_path(path) for path in generated if path.exists()]
            job.status = "completed"
            job.progress = 100
            job.phase = "Completed"
            job.finished_at = utc_now()
        job.log("Scan completed.")
    except Exception as exc:
        with job._lock:
            job.status = "failed"
            job.error = str(exc)
            job.phase = "Failed"
            job.finished_at = utc_now()
        job.log(f"Scan failed: {exc}")
    finally:
        config.STEALTH_MODE = old_stealth


def app_bootstrap(username: str) -> dict[str, Any]:
    modules = [
        {
            "id": module_id,
            "name": name,
            "description": MODULE_DESCRIPTIONS.get(module_id, ""),
            "default": module_id in DEFAULT_MODULES,
            "danger": module_id == 11,
        }
        for module_id, (name, _) in MODULE_REGISTRY.items()
    ]
    api_keys = {
        key: bool(value)
        for key, value in config.API_KEYS.items()
    }
    return {
        "app": {
            "title": APP_TITLE,
            "tagline": APP_TAGLINE,
            "company": COMPANY_NAME,
        },
        "modules": modules,
        "profiles": PROFILES,
        "api_keys": api_keys,
        "auth_required": auth_required(),
        "auth_mode": auth_mode(),
        "user": username,
        "user_role": user_role(username),
        "is_admin": is_admin_user(username),
        "can_scan": can_start_scan(username),
        "roles": USER_ROLES,
        "users": list_managed_users() if is_admin_user(username) else [],
        "api_key_status": list_api_key_status() if is_admin_user(username) else [],
        "max_workers": max(1, MAX_WORKERS),
        "jobs": JOBS.list(),
        "reports": list_reports(),
    }


class WebHandler(BaseHTTPRequestHandler):
    server_version = "LinkedItCyberScan/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[web] {self.address_string()} - {fmt % args}")

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8",
              headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any] | list[Any]) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length else b""

    def _read_json(self) -> dict[str, Any]:
        raw = self._read_body()
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _current_user(self) -> str | None:
        if not auth_required():
            return "local"
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = jar.get(SESSION_COOKIE)
        if morsel:
            username = verify_session(morsel.value)
            if username:
                if has_managed_users():
                    managed = get_managed_user(username)
                    if managed and managed.get("active", True):
                        return username
                elif username in WEB_USERS or not WEB_USERS:
                    return username

        legacy = jar.get("easm_token")
        if legacy and WEB_TOKEN and secrets.compare_digest(legacy.value, WEB_TOKEN):
            return "team"
        return None

    def _authorized(self) -> bool:
        return self._current_user() is not None

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        path = urlsplit(self.path).path
        if setup_required():
            if path.startswith("/api/"):
                self._json(428, {"error": "Initial admin setup required."})
            else:
                self._send(200, render_setup().encode("utf-8"))
            return False
        if path.startswith("/api/"):
            self._json(401, {"error": "Authentication required."})
        else:
            self._send(200, render_login().encode("utf-8"))
        return False

    def _require_admin(self) -> bool:
        if self._require_auth() and is_admin_user(self._current_user()):
            return True
        self._json(403, {"error": "Admin permissions required."})
        return False

    def _require_scan_permission(self) -> bool:
        if self._require_auth() and can_start_scan(self._current_user()):
            return True
        self._json(403, {"error": "Scanner permissions required."})
        return False

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/setup":
            if setup_required():
                self._send(200, render_setup().encode("utf-8"))
            else:
                self._send(303, b"", "text/plain; charset=utf-8", {"Location": "/login"})
            return
        if path == "/login":
            self._send(200, (render_setup() if setup_required() else render_login()).encode("utf-8"))
            return
        if path == "/logout":
            self._send(
                303,
                b"",
                "text/plain; charset=utf-8",
                {
                    "Set-Cookie": f"{SESSION_COOKIE}=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/",
                    "Location": "/login",
                },
            )
            return
        if not self._require_auth():
            return
        if path == "/":
            self._send(303, b"", "text/plain; charset=utf-8", {"Location": "/dashboard"})
            return
        if path == "/admin":
            self._send(303, b"", "text/plain; charset=utf-8", {"Location": "/admin/users"})
            return
        if path in {"/dashboard", "/scans", "/reports", "/admin/users", "/admin/api-keys", "/index.html"}:
            self._send(200, APP_HTML.encode("utf-8"))
            return
        if path == "/api/bootstrap":
            self._json(200, app_bootstrap(self._current_user() or "local"))
            return
        if path == "/api/scans":
            self._json(200, {"jobs": JOBS.list()})
            return
        if path.startswith("/api/scans/"):
            job_id = path.rsplit("/", 1)[-1]
            job = JOBS.get(job_id)
            if not job:
                self._json(404, {"error": "Scan job not found."})
                return
            self._json(200, job.snapshot())
            return
        if path == "/api/reports":
            self._json(200, {"reports": list_reports()})
            return
        if path == "/api/users":
            if not self._require_admin():
                return
            self._json(200, {"users": list_managed_users(), "roles": USER_ROLES})
            return
        if path == "/api/admin/api-keys":
            if not self._require_admin():
                return
            self._json(200, {"api_keys": list_api_key_status()})
            return
        if path.startswith("/reports/"):
            try:
                report_path = safe_report_path(path)
            except FileNotFoundError:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
                return
            content_type = mimetypes.guess_type(str(report_path))[0] or "application/octet-stream"
            self._send(200, report_path.read_bytes(), content_type)
            return
        self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:
        path = urlsplit(self.path).path
        if setup_required() and path != "/setup":
            body = b"Initial admin setup required."
            self.send_response(428)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        if not self._authorized():
            body = b"Authentication required."
            self.send_response(401)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        if path == "/":
            self.send_response(303)
            self.send_header("Location", "/dashboard")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/admin":
            self.send_response(303)
            self.send_header("Location", "/admin/users")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path in {"/", "/dashboard", "/scans", "/reports", "/admin/users", "/admin/api-keys", "/index.html"}:
            body = APP_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        if path.startswith("/reports/"):
            try:
                report_path = safe_report_path(path)
            except FileNotFoundError:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            content_type = mimetypes.guess_type(str(report_path))[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(report_path.stat().st_size))
            self.end_headers()
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path == "/setup":
            if not setup_required():
                self._send(303, b"", "text/plain; charset=utf-8", {"Location": "/login"})
                return
            raw = self._read_body().decode("utf-8")
            form = parse_qs(raw)
            username = (form.get("username") or [""])[0].strip()
            password = (form.get("password") or [""])[0]
            confirm = (form.get("confirm") or [""])[0]
            if password != confirm:
                self._send(400, render_setup("Passwords do not match.").encode("utf-8"))
                return
            try:
                upsert_managed_user(username, password, "admin", True, "setup")
                session = sign_session(username)
                self._send(
                    303,
                    b"",
                    "text/plain; charset=utf-8",
                    {
                        "Set-Cookie": (
                            f"{SESSION_COOKIE}={session}; Max-Age={SESSION_TTL_SECONDS}; "
                            "HttpOnly; SameSite=Lax; Path=/"
                        ),
                        "Location": "/dashboard",
                    },
                )
            except Exception as exc:
                self._send(400, render_setup(str(exc)).encode("utf-8"))
            return

        if path == "/login":
            raw = self._read_body().decode("utf-8")
            form = parse_qs(raw)
            username = (form.get("username") or [""])[0].strip()
            password = (form.get("password") or [""])[0]
            user = verify_login(username, password)
            if user:
                session = sign_session(user)
                self._send(
                    303,
                    b"",
                    "text/plain; charset=utf-8",
                    {
                        "Set-Cookie": (
                            f"{SESSION_COOKIE}={session}; Max-Age={SESSION_TTL_SECONDS}; "
                            "HttpOnly; SameSite=Lax; Path=/"
                        ),
                        "Location": "/dashboard",
                    },
                )
                return
            self._send(403, render_login("Invalid login.").encode("utf-8"))
            return

        if not self._require_auth():
            return

        if path == "/api/scans":
            try:
                payload = self._read_json()
                domain = validate_domain(str(payload.get("domain", "")))
                modules = parse_modules(payload.get("modules"))
                stealth = bool(payload.get("stealth", False))
                exploit = bool(payload.get("exploit", False))
                fresh = bool(payload.get("fresh", False))
                authorized = bool(payload.get("authorized", False))
                if not self._require_scan_permission():
                    return
                if not authorized:
                    raise ValueError("Confirm customer authorization before starting the scan.")
                if 11 in modules and not exploit:
                    raise ValueError("Active exploitation needs the exploit switch.")
                user = self._current_user() or "local"
                job = JOBS.create(domain, modules, stealth, exploit, fresh, authorized, user)
                job.log(f"Queued by {user}.")
                EXECUTOR.submit(run_scan_job, job)
                self._json(201, {"job": job.snapshot()})
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return

        if path == "/api/users":
            if not self._require_admin():
                return
            try:
                payload = self._read_json()
                user = upsert_managed_user(
                    username=str(payload.get("username", "")),
                    password=str(payload.get("password", "")),
                    role=str(payload.get("role", "scanner")),
                    active=bool(payload.get("active", True)),
                    updated_by=self._current_user() or "local",
                )
                self._json(200, {"user": user, "users": list_managed_users()})
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return

        if path == "/api/admin/api-keys":
            if not self._require_admin():
                return
            try:
                payload = self._read_json()
                self._json(200, {"api_keys": update_api_keys(payload)})
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return

        self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_DELETE(self) -> None:
        path = urlsplit(self.path).path
        if not self._require_auth():
            return
        if path.startswith("/api/users/"):
            if not self._require_admin():
                return
            try:
                username = unquote(path.rsplit("/", 1)[-1])
                delete_managed_user(username)
                self._json(200, {"ok": True, "users": list_managed_users()})
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        self._send(404, b"Not found", "text/plain; charset=utf-8")


def render_setup(error: str = "") -> str:
    error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""
    page = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Setup link-ed.it CyberScan</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; }
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 24px;
      font-family: "Inter", ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #eef2fb;
      background:
        radial-gradient(900px 520px at 15% -10%, rgba(45, 212, 191, .20), transparent 60%),
        radial-gradient(820px 540px at 100% 0%, rgba(99, 102, 241, .22), transparent 55%),
        linear-gradient(180deg, #070b16, #0b1124);
      background-attachment: fixed;
    }
    main {
      position: relative;
      width: min(440px, calc(100vw - 32px));
      background: rgba(18, 25, 48, .72);
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      border: 1px solid rgba(140, 160, 210, .16);
      border-radius: 20px;
      padding: 34px 32px;
      box-shadow: 0 30px 80px -30px rgba(0, 0, 0, .8);
      overflow: hidden;
    }
    main::before {
      content: "";
      position: absolute;
      inset: 0 0 auto 0;
      height: 3px;
      background: linear-gradient(135deg, #2dd4bf, #22d3ee 45%, #6366f1);
    }
    .mark {
      width: 52px;
      height: 52px;
      display: grid;
      place-items: center;
      border-radius: 14px;
      background: linear-gradient(135deg, #2dd4bf, #22d3ee 45%, #6366f1);
      color: #04121a;
      font-weight: 900;
      font-size: 22px;
      margin-bottom: 20px;
      font-family: "Poppins", "Inter", sans-serif;
      box-shadow: 0 12px 30px -10px rgba(45, 212, 191, .6);
    }
    h1 {
      margin: 0;
      font-size: 26px;
      font-family: "Poppins", "Inter", sans-serif;
      font-weight: 800;
      letter-spacing: -.01em;
    }
    .mode { margin: 8px 0 24px; color: #97a3c4; font-size: 13.5px; }
    label {
      display: block;
      font-size: 12px;
      font-weight: 700;
      margin-bottom: 8px;
      color: #cdd6ee;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    input {
      width: 100%;
      min-height: 48px;
      border: 1px solid rgba(140, 160, 210, .2);
      border-radius: 12px;
      padding: 0 14px;
      font: inherit;
      margin-bottom: 16px;
      background: rgba(8, 12, 24, .6);
      color: #f4f7ff;
      transition: border-color .15s ease, box-shadow .15s ease;
    }
    input::placeholder { color: #6c7799; }
    input:focus {
      outline: none;
      border-color: #2dd4bf;
      box-shadow: 0 0 0 4px rgba(45, 212, 191, .18);
    }
    button {
      width: 100%;
      min-height: 48px;
      margin-top: 6px;
      border: 0;
      border-radius: 12px;
      background: linear-gradient(135deg, #2dd4bf, #22d3ee 50%, #6366f1);
      color: #04121a;
      font-weight: 800;
      font-size: 15px;
      cursor: pointer;
      font-family: "Poppins", "Inter", sans-serif;
      box-shadow: 0 14px 34px -14px rgba(45, 212, 191, .7);
      transition: transform .12s ease, box-shadow .12s ease, filter .12s ease;
    }
    button:hover {
      transform: translateY(-1px);
      filter: brightness(1.06);
      box-shadow: 0 18px 40px -14px rgba(45, 212, 191, .85);
    }
    button:active { transform: translateY(0); }
    .error { color: #fb7185; margin: 0 0 16px; font-weight: 700; font-size: 13.5px; }
  </style>
</head>
<body>
  <main>
    <div class="mark">L</div>
    <h1>Initial Admin Setup</h1>
    <p class="mode">Create the first internal employee admin for link-ed.it CyberScan.</p>
    __ERROR_HTML__
    <form method="post" action="/setup">
      <label for="username">Admin user</label>
      <input id="username" name="username" type="text" autocomplete="username" autofocus>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="new-password">
      <label for="confirm">Confirm password</label>
      <input id="confirm" name="confirm" type="password" autocomplete="new-password">
      <button type="submit">Create admin</button>
    </form>
  </main>
</body>
</html>"""
    return page.replace("__ERROR_HTML__", error_html)


def render_login(error: str = "") -> str:
    mode_text = "Team login" if has_managed_users() or WEB_USERS else "Shared access token"
    error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""
    username_value = "" if has_managed_users() or WEB_USERS else "team"
    page = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>link-ed.it CyberScan Login</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; }
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 24px;
      font-family: "Inter", ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #eef2fb;
      background:
        radial-gradient(900px 520px at 15% -10%, rgba(45, 212, 191, .20), transparent 60%),
        radial-gradient(820px 540px at 100% 0%, rgba(99, 102, 241, .22), transparent 55%),
        linear-gradient(180deg, #070b16, #0b1124);
      background-attachment: fixed;
    }
    main {
      position: relative;
      width: min(440px, calc(100vw - 32px));
      background: rgba(18, 25, 48, .72);
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      border: 1px solid rgba(140, 160, 210, .16);
      border-radius: 20px;
      padding: 34px 32px;
      box-shadow: 0 30px 80px -30px rgba(0, 0, 0, .8);
      overflow: hidden;
    }
    main::before {
      content: "";
      position: absolute;
      inset: 0 0 auto 0;
      height: 3px;
      background: linear-gradient(135deg, #2dd4bf, #22d3ee 45%, #6366f1);
    }
    .mark {
      width: 52px;
      height: 52px;
      display: grid;
      place-items: center;
      border-radius: 14px;
      background: linear-gradient(135deg, #2dd4bf, #22d3ee 45%, #6366f1);
      color: #04121a;
      font-weight: 900;
      font-size: 22px;
      margin-bottom: 20px;
      font-family: "Poppins", "Inter", sans-serif;
      box-shadow: 0 12px 30px -10px rgba(45, 212, 191, .6);
    }
    h1 {
      margin: 0;
      font-size: 26px;
      font-family: "Poppins", "Inter", sans-serif;
      font-weight: 800;
      letter-spacing: -.01em;
    }
    .mode { margin: 8px 0 24px; color: #97a3c4; font-size: 13.5px; }
    label {
      display: block;
      font-size: 12px;
      font-weight: 700;
      margin-bottom: 8px;
      color: #cdd6ee;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    input {
      width: 100%;
      min-height: 48px;
      border: 1px solid rgba(140, 160, 210, .2);
      border-radius: 12px;
      padding: 0 14px;
      font: inherit;
      margin-bottom: 16px;
      background: rgba(8, 12, 24, .6);
      color: #f4f7ff;
      transition: border-color .15s ease, box-shadow .15s ease;
    }
    input::placeholder { color: #6c7799; }
    input:focus {
      outline: none;
      border-color: #2dd4bf;
      box-shadow: 0 0 0 4px rgba(45, 212, 191, .18);
    }
    button {
      width: 100%;
      min-height: 48px;
      margin-top: 6px;
      border: 0;
      border-radius: 12px;
      background: linear-gradient(135deg, #2dd4bf, #22d3ee 50%, #6366f1);
      color: #04121a;
      font-weight: 800;
      font-size: 15px;
      cursor: pointer;
      font-family: "Poppins", "Inter", sans-serif;
      box-shadow: 0 14px 34px -14px rgba(45, 212, 191, .7);
      transition: transform .12s ease, box-shadow .12s ease, filter .12s ease;
    }
    button:hover {
      transform: translateY(-1px);
      filter: brightness(1.06);
      box-shadow: 0 18px 40px -14px rgba(45, 212, 191, .85);
    }
    button:active { transform: translateY(0); }
    .error { color: #fb7185; margin: 0 0 16px; font-weight: 700; font-size: 13.5px; }
  </style>
</head>
<body>
  <main>
    <div class="mark">L</div>
    <h1>link-ed.it CyberScan</h1>
    <p class="mode">__MODE_TEXT__</p>
    __ERROR_HTML__
    <form method="post" action="/login">
      <label for="username">User</label>
      <input id="username" name="username" type="text" value="__USERNAME__" autocomplete="username" autofocus>
      <label for="password">Password / token</label>
      <input id="password" name="password" type="password" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>"""
    return (
        page
        .replace("__MODE_TEXT__", html.escape(mode_text))
        .replace("__ERROR_HTML__", error_html)
        .replace("__USERNAME__", html.escape(username_value))
    )


APP_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>link-ed.it CyberScan</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-0: #070b16;
      --bg-1: #0b1124;
      --surface: rgba(18, 25, 48, .72);
      --surface-2: rgba(13, 19, 38, .55);
      --line: rgba(140, 160, 210, .14);
      --line-soft: rgba(140, 160, 210, .08);
      --text: #eef2fb;
      --muted: #97a3c4;
      --muted-2: #6c7799;
      --brand: #2dd4bf;
      --brand-2: #22d3ee;
      --brand-3: #6366f1;
      --grad: linear-gradient(135deg, #2dd4bf 0%, #22d3ee 48%, #6366f1 100%);
      --green: #2dd4bf;
      --green-soft: rgba(45, 212, 191, .16);
      --red: #fb7185;
      --red-soft: rgba(244, 63, 94, .16);
      --orange: #fbbf24;
      --orange-soft: rgba(251, 146, 60, .16);
      --yellow: #fbbf24;
      --yellow-soft: rgba(250, 204, 21, .14);
      --blue: #7dd3fc;
      --blue-soft: rgba(56, 189, 248, .14);
      --radius: 16px;
      --radius-sm: 12px;
      --shadow: 0 24px 60px -28px rgba(0, 0, 0, .75);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Inter", ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      line-height: 1.5;
      background:
        radial-gradient(1100px 620px at 10% -8%, rgba(45, 212, 191, .15), transparent 60%),
        radial-gradient(960px 640px at 100% 0%, rgba(99, 102, 241, .17), transparent 55%),
        linear-gradient(180deg, var(--bg-0), var(--bg-1));
      background-attachment: fixed;
    }
    h1, h2, h3 { font-family: "Poppins", "Inter", sans-serif; letter-spacing: -.01em; }
    button, input, select { font: inherit; }
    button { cursor: pointer; }
    ::-webkit-scrollbar { width: 10px; height: 10px; }
    ::-webkit-scrollbar-thumb { background: rgba(140, 160, 210, .22); border-radius: 999px; }
    ::-webkit-scrollbar-track { background: transparent; }

    /* ---------- Topbar ---------- */
    .topbar {
      min-height: 74px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      padding: 0 28px;
      background: rgba(9, 13, 26, .72);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 20;
    }
    .brand { display: flex; align-items: center; gap: 13px; min-width: 0; }
    .brand-mark {
      width: 40px;
      height: 40px;
      display: grid;
      place-items: center;
      border-radius: 12px;
      background: var(--grad);
      color: #04121a;
      font-weight: 900;
      font-family: "Poppins", "Inter", sans-serif;
      box-shadow: 0 10px 26px -10px rgba(45, 212, 191, .65);
    }
    .brand h1 { margin: 0; font-size: 19px; font-weight: 800; }
    .brand p { margin: 2px 0 0; color: var(--muted); font-size: 12px; }
    .primary-nav {
      display: flex;
      align-items: center;
      gap: 4px;
      min-height: 42px;
      padding: 5px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(8, 13, 24, .5);
    }
    .primary-nav a {
      min-height: 32px;
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 0 14px;
      color: var(--muted);
      text-decoration: none;
      font-size: 13px;
      font-weight: 700;
      transition: color .15s ease, background .15s ease;
    }
    .primary-nav a:hover { color: #fff; background: rgba(140, 160, 210, .12); }
    .primary-nav a.active { color: #04121a; background: var(--grad); box-shadow: 0 8px 20px -10px rgba(45, 212, 191, .6); }
    .top-actions { display: flex; align-items: center; justify-content: flex-end; gap: 12px; flex-wrap: wrap; }
    .api-strip { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 6px; }
    .api-key {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      min-height: 26px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 0 10px;
      font-size: 12px;
      font-weight: 600;
      background: rgba(8, 13, 24, .5);
      color: var(--muted);
    }
    .api-key.on { color: #7df3df; background: rgba(45, 212, 191, .14); border-color: rgba(45, 212, 191, .34); }
    .api-key.off { color: #f3c97a; background: rgba(250, 204, 21, .12); border-color: rgba(250, 204, 21, .32); }
    .userbox {
      display: flex;
      align-items: center;
      gap: 9px;
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 0 8px 0 14px;
      background: rgba(8, 13, 24, .5);
      color: var(--text);
      font-size: 13px;
      font-weight: 700;
    }
    .logout {
      min-height: 26px;
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 0 12px;
      color: #04121a;
      background: var(--grad);
      text-decoration: none;
      font-size: 12px;
      font-weight: 800;
    }
    .logout:hover { filter: brightness(1.07); }

    /* ---------- Layout ---------- */
    .layout {
      width: min(1520px, calc(100vw - 36px));
      margin: 26px auto 56px;
      display: grid;
      grid-template-columns: minmax(380px, 460px) minmax(0, 1fr);
      gap: 18px;
      align-items: start;
    }
    .route-hidden { display: none !important; }
    .workspace { display: grid; gap: 18px; }
    .layout.route-reports,
    .layout.route-dashboard,
    .layout.route-admin-users,
    .layout.route-admin-api-keys { grid-template-columns: minmax(0, 1fr); }
    .layout.route-reports .workspace,
    .layout.route-dashboard .workspace,
    .layout.route-admin-users .workspace,
    .layout.route-admin-api-keys .workspace { max-width: 1200px; width: 100%; margin: 0 auto; }

    /* ---------- Panels ---------- */
    .panel {
      background: var(--surface);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .panel-head {
      min-height: 58px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 0 20px;
      border-bottom: 1px solid var(--line);
      background: rgba(255, 255, 255, .02);
    }
    .panel-head h2 { margin: 0; font-size: 15px; font-weight: 700; color: #f6f8ff; }
    .panel-body { padding: 20px; color: var(--muted); }

    /* ---------- Forms ---------- */
    .field { margin-bottom: 18px; }
    .field label, .admin-form label {
      display: block;
      color: #cdd6ee;
      font-size: 11px;
      font-weight: 700;
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: .05em;
    }
    input[type="text"], input[type="password"], select {
      width: 100%;
      min-height: 46px;
      border: 1px solid rgba(140, 160, 210, .2);
      border-radius: var(--radius-sm);
      padding: 0 14px;
      background: rgba(8, 12, 24, .55);
      color: var(--text);
      transition: border-color .15s ease, box-shadow .15s ease;
    }
    input::placeholder { color: var(--muted-2); }
    input[type="text"]:focus, input[type="password"]:focus, select:focus {
      outline: none;
      border-color: var(--brand);
      box-shadow: 0 0 0 4px rgba(45, 212, 191, .16);
    }

    /* ---------- Profiles ---------- */
    .profiles { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .profile-btn {
      min-height: 40px;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      background: rgba(8, 13, 24, .4);
      color: #d6dee9;
      font-weight: 700;
      transition: all .15s ease;
    }
    .profile-btn:hover { border-color: rgba(140, 160, 210, .4); background: rgba(140, 160, 210, .08); }
    .profile-btn.active {
      color: #04121a;
      background: var(--grad);
      border-color: transparent;
      box-shadow: 0 10px 24px -12px rgba(45, 212, 191, .6);
    }

    /* ---------- Modules ---------- */
    .modules { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; }
    .module {
      display: grid;
      grid-template-columns: 22px minmax(0, 1fr);
      gap: 9px;
      min-height: 72px;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      background: var(--surface-2);
      transition: border-color .15s ease, background .15s ease;
    }
    .module.danger { background: rgba(244, 63, 94, .08); border-color: rgba(244, 63, 94, .28); }
    .module input { width: 18px; height: 18px; margin-top: 2px; accent-color: var(--brand); }
    .module-title { display: block; font-size: 13px; font-weight: 700; color: #eef2fb; overflow-wrap: anywhere; }
    .module-desc { display: block; margin-top: 3px; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
    .module:has(input:checked) { background: rgba(45, 212, 191, .12); border-color: rgba(45, 212, 191, .42); }
    .module.danger:has(input:checked) { background: rgba(244, 63, 94, .16); border-color: rgba(244, 63, 94, .5); }

    /* ---------- Toggles ---------- */
    .toggles { display: grid; gap: 10px; }
    .switch-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 14px;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      background: var(--surface-2);
    }
    .switch-row strong { display: block; font-size: 13px; color: #eef2fb; }
    .switch-row span { display: block; color: var(--muted); font-size: 12px; }
    .switch-row input { width: 42px; height: 22px; accent-color: var(--brand); }

    /* ---------- Buttons ---------- */
    .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 18px; }
    .primary, .secondary {
      min-height: 46px;
      border-radius: var(--radius-sm);
      border: 1px solid transparent;
      padding: 0 18px;
      font-weight: 800;
      font-family: "Poppins", "Inter", sans-serif;
      transition: transform .12s ease, box-shadow .12s ease, filter .12s ease, background .15s ease;
    }
    .primary {
      background: var(--grad);
      color: #04121a;
      flex: 1 1 210px;
      box-shadow: 0 14px 34px -16px rgba(45, 212, 191, .7);
    }
    .primary:hover { transform: translateY(-1px); filter: brightness(1.06); box-shadow: 0 18px 40px -16px rgba(45, 212, 191, .85); }
    .primary:active { transform: translateY(0); }
    .primary:disabled { background: rgba(140, 160, 210, .16); color: var(--muted-2); box-shadow: none; cursor: not-allowed; filter: none; transform: none; }
    .secondary { background: rgba(140, 160, 210, .06); color: var(--text); border-color: var(--line); }
    .secondary:hover { background: rgba(140, 160, 210, .14); border-color: rgba(140, 160, 210, .34); }

    /* ---------- Toolbar / icons ---------- */
    .toolbar { display: flex; align-items: center; gap: 8px; }
    .icon-button {
      width: 38px;
      height: 38px;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      background: rgba(140, 160, 210, .06);
      color: var(--text);
      font-size: 18px;
      line-height: 1;
      transition: all .15s ease;
    }
    .icon-button:hover { background: rgba(140, 160, 210, .14); border-color: rgba(140, 160, 210, .34); }

    /* ---------- Empty ---------- */
    .empty {
      min-height: 96px;
      display: grid;
      place-items: center;
      color: var(--muted);
      background: var(--surface-2);
      border-radius: var(--radius-sm);
      border: 1px dashed rgba(140, 160, 210, .26);
      text-align: center;
      padding: 16px;
    }

    /* ---------- Metrics ---------- */
    .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
    .metric {
      position: relative;
      min-height: 96px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      padding: 16px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .metric::before {
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 3px;
      background: var(--grad);
    }
    .metric .label { color: var(--muted); font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .05em; }
    .metric .value { margin-top: 8px; font-size: 30px; line-height: 1; font-weight: 800; font-family: "Poppins", "Inter", sans-serif; color: #f6f8ff; }
    .metric .hint { margin-top: 8px; color: var(--muted); font-size: 12px; }

    /* ---------- Jobs ---------- */
    .job-list { display: grid; gap: 12px; }
    .job {
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--surface-2);
      overflow: hidden;
      transition: transform .15s ease, box-shadow .15s ease, border-color .15s ease;
    }
    .job:hover { transform: translateY(-1px); border-color: rgba(140, 160, 210, .3); box-shadow: 0 18px 44px -22px rgba(0, 0, 0, .8); }
    .job-main { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px; padding: 14px; }
    .job h3 { margin: 0; font-size: 15px; font-weight: 700; color: #f6f8ff; overflow-wrap: anywhere; }
    .job-meta { margin-top: 4px; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
    .status {
      align-self: start;
      border-radius: 999px;
      padding: 5px 11px;
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: .03em;
    }
    .status.running, .status.completed { color: #7df3df; background: rgba(45, 212, 191, .16); }
    .status.queued { color: #f3c97a; background: rgba(250, 204, 21, .14); }
    .status.failed { color: #fda4af; background: rgba(244, 63, 94, .16); }
    .progress { height: 8px; margin: 0 14px 14px; border-radius: 999px; background: rgba(140, 160, 210, .16); overflow: hidden; }
    .progress span { display: block; height: 100%; background: var(--grad); width: 0; transition: width .3s ease; }
    .logs {
      margin: 0;
      padding: 12px 14px;
      max-height: 180px;
      overflow: auto;
      border-top: 1px solid var(--line);
      background: rgba(3, 6, 16, .7);
      color: #c9d6e2;
      font: 12px/1.5 "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      white-space: pre-wrap;
    }

    /* ---------- Tables ---------- */
    .reports, .users-table { width: 100%; border-collapse: collapse; }
    .reports th, .users-table th {
      text-align: left;
      font-size: 11px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: .05em;
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
    }
    .reports td, .users-table td {
      border-bottom: 1px solid var(--line-soft);
      padding: 12px 8px;
      vertical-align: top;
      font-size: 13px;
      color: #dbe2f3;
      overflow-wrap: anywhere;
    }
    .users-table td { vertical-align: middle; }
    .reports tbody tr:hover { background: rgba(140, 160, 210, .05); }

    /* ---------- Admin ---------- */
    .admin-grid { display: grid; grid-template-columns: minmax(240px, 320px) minmax(0, 1fr); gap: 16px; align-items: start; }
    .admin-form {
      display: grid;
      gap: 12px;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--surface-2);
    }
    .admin-form label { display: grid; gap: 6px; }
    .inline-check {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      min-height: 44px;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      padding: 0 14px;
      background: rgba(8, 13, 24, .4);
      font-size: 13px;
      font-weight: 700;
      color: #eef2fb;
      text-transform: none;
      letter-spacing: 0;
    }
    .key-list {
      display: grid;
      gap: 12px;
    }
    .key-row {
      display: grid;
      grid-template-columns: minmax(220px, .85fr) minmax(260px, 1fr) 120px;
      gap: 14px;
      align-items: start;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--surface-2);
      padding: 16px;
    }
    .key-row h3 {
      margin: 0;
      font-size: 14px;
      font-weight: 700;
      color: #f6f8ff;
    }
    .key-row p {
      margin: 5px 0 0;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
    }
    .key-row code {
      display: inline-flex;
      margin-top: 8px;
      color: #7df3df;
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .key-controls {
      display: grid;
      gap: 8px;
    }
    .key-clear {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }
    .key-status {
      justify-self: end;
      align-self: start;
      border-radius: 999px;
      padding: 5px 10px;
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: .03em;
      background: rgba(244, 63, 94, .16);
      color: #fda4af;
    }
    .key-status.on {
      background: rgba(45, 212, 191, .16);
      color: #7df3df;
    }

    /* ---------- Dashboard overview ---------- */
    .dashboard-grid { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(280px, .9fr); gap: 16px; }
    .overview-block {
      min-height: 150px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--surface-2);
      padding: 18px;
    }
    .overview-block h3 { margin: 0 0 14px; font-size: 14px; font-weight: 700; color: #f6f8ff; }
    .overview-main { font-size: 28px; line-height: 1.1; font-weight: 800; font-family: "Poppins", "Inter", sans-serif; color: #f6f8ff; overflow-wrap: anywhere; }
    .overview-meta { margin-top: 8px; color: var(--muted); font-size: 13px; }
    .compact-list { display: grid; gap: 8px; }
    .compact-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      min-height: 46px;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      padding: 9px 12px;
      background: rgba(8, 13, 24, .4);
    }
    .compact-row strong { display: block; color: #eef2fb; font-size: 13px; overflow-wrap: anywhere; }
    .compact-row span { display: block; margin-top: 2px; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }

    /* ---------- Risk / chips ---------- */
    .risk {
      display: inline-flex;
      min-width: 70px;
      justify-content: center;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 11px;
      font-weight: 800;
      background: rgba(56, 189, 248, .14);
      color: #a7c7f8;
    }
    .risk.CRITICAL, .risk.HIGH { background: rgba(244, 63, 94, .16); color: #fda4af; }
    .risk.MEDIUM { background: rgba(251, 146, 60, .16); color: #f3c97a; }
    .risk.LOW { background: rgba(74, 222, 128, .14); color: #9be8a0; }
    .chip-row { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
    .chip {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 0 10px;
      background: rgba(140, 160, 210, .12);
      color: #cbd5e1;
      font-size: 11px;
      font-weight: 700;
    }
    .chip.danger { background: rgba(244, 63, 94, .16); color: #fda4af; }
    .chip.ok { background: rgba(45, 212, 191, .16); color: #7df3df; }

    /* ---------- Link actions ---------- */
    .link-actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .link-actions a {
      min-height: 32px;
      display: inline-flex;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      padding: 0 11px;
      color: var(--text);
      text-decoration: none;
      font-weight: 700;
      font-size: 13px;
      background: rgba(140, 160, 210, .06);
      transition: all .15s ease;
    }
    .link-actions a:hover { background: rgba(140, 160, 210, .14); border-color: rgba(140, 160, 210, .34); }

    /* ---------- Notice ---------- */
    .notice {
      display: none;
      margin-top: 14px;
      border-radius: var(--radius-sm);
      padding: 12px 14px;
      background: rgba(244, 63, 94, .14);
      border: 1px solid rgba(244, 63, 94, .32);
      color: #fda4af;
      font-weight: 700;
      overflow-wrap: anywhere;
    }
    .notice.show { display: block; }

    /* ---------- Responsive ---------- */
    @media (max-width: 980px) {
      .topbar { align-items: flex-start; flex-direction: column; padding: 16px; gap: 12px; }
      .api-strip { justify-content: flex-start; }
      .top-actions { justify-content: flex-start; }
      .layout { grid-template-columns: 1fr; width: min(760px, calc(100vw - 24px)); }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .admin-grid { grid-template-columns: 1fr; }
      .dashboard-grid { grid-template-columns: 1fr; }
      .key-row { grid-template-columns: 1fr; }
      .key-status { justify-self: start; }
    }
    @media (max-width: 560px) {
      .modules, .profiles { grid-template-columns: 1fr; }
      .panel-body { padding: 14px; }
      .job-main { grid-template-columns: 1fr; }
      .reports th:nth-child(4), .reports td:nth-child(4) { display: none; }
      .metrics { grid-template-columns: 1fr; }
      .primary-nav { flex-wrap: wrap; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">L</div>
      <div>
        <h1>link-ed.it CyberScan</h1>
        <p>Internal customer-domain security scans</p>
      </div>
    </div>
    <nav class="primary-nav" aria-label="Main navigation">
      <a href="/dashboard" data-route-link="dashboard">Dashboard</a>
      <a href="/scans" data-route-link="scans">Scans</a>
      <a href="/reports" data-route-link="reports">Reports</a>
      <a href="/admin/users" data-route-link="admin-users" data-admin-only="true">Users</a>
      <a href="/admin/api-keys" data-route-link="admin-api-keys" data-admin-only="true">API Keys</a>
    </nav>
    <div class="top-actions">
      <div id="apiKeys" class="api-strip"></div>
      <div class="userbox">
        <span id="userLabel">local</span>
        <a class="logout" href="/logout">Logout</a>
      </div>
    </div>
  </header>

  <main id="appLayout" class="layout route-dashboard">
    <section id="scanPanel" class="panel route-hidden">
      <div class="panel-head">
        <h2>Customer Scan</h2>
      </div>
      <div class="panel-body">
        <div class="field">
          <label for="domain">Customer domain</label>
          <input id="domain" type="text" placeholder="kunde.de" autocomplete="off">
        </div>

        <div class="field">
          <label>Profile</label>
          <div id="profiles" class="profiles"></div>
        </div>

        <div class="field">
          <label>Modules</label>
          <div id="modules" class="modules"></div>
        </div>

        <div class="field">
          <label>Options</label>
          <div class="toggles">
            <label class="switch-row">
              <span><strong>Rate jitter</strong><span>Jitter and browser-like request headers</span></span>
              <input id="stealth" type="checkbox" checked>
            </label>
            <label class="switch-row">
              <span><strong>Exploit mode</strong><span>Required for module 11</span></span>
              <input id="exploit" type="checkbox">
            </label>
            <label class="switch-row">
              <span><strong>Fresh scan</strong><span>Ignore stored checkpoint</span></span>
              <input id="fresh" type="checkbox">
            </label>
            <label class="switch-row">
              <span><strong>Customer authorization</strong><span>Written approval or contract scope is confirmed</span></span>
              <input id="authorized" type="checkbox">
            </label>
          </div>
        </div>

        <div class="actions">
          <button id="startScan" class="primary" type="button">Start customer scan</button>
          <button id="selectSafe" class="secondary" type="button">Internal default</button>
        </div>
        <div id="notice" class="notice"></div>
      </div>
    </section>

    <div class="workspace">
      <section id="metrics" class="metrics"></section>

      <section id="dashboardPanel" class="panel">
        <div class="panel-head">
          <h2>Operations Overview</h2>
        </div>
        <div class="panel-body">
          <div id="dashboardContent"></div>
        </div>
      </section>

      <section id="jobsPanel" class="panel route-hidden">
        <div class="panel-head">
          <h2>Scans</h2>
          <div class="toolbar">
            <button id="refresh" class="icon-button" type="button" title="Refresh" aria-label="Refresh">&#8635;</button>
          </div>
        </div>
        <div class="panel-body">
          <div id="jobs" class="job-list"></div>
        </div>
      </section>

      <section id="reportsPanel" class="panel route-hidden">
        <div class="panel-head">
          <h2>Reports</h2>
        </div>
        <div class="panel-body">
          <div id="reports"></div>
        </div>
      </section>

      <section id="adminPanel" class="panel route-hidden" hidden>
        <div class="panel-head">
          <h2>User Management</h2>
        </div>
        <div class="panel-body">
          <div class="admin-grid">
            <div class="admin-form">
              <label>Username
                <input id="adminUsername" type="text" placeholder="max.mustermann" autocomplete="off">
              </label>
              <label>Password
                <input id="adminPassword" type="password" placeholder="leave blank to keep existing password" autocomplete="new-password">
              </label>
              <label>Role
                <select id="adminRole"></select>
              </label>
              <label class="inline-check">
                <span>Active</span>
                <input id="adminActive" type="checkbox" checked>
              </label>
              <button id="saveUser" class="primary" type="button">Save user</button>
              <div id="adminNotice" class="notice"></div>
            </div>
            <div id="users"></div>
          </div>
        </div>
      </section>

      <section id="apiKeysPanel" class="panel route-hidden" hidden>
        <div class="panel-head">
          <h2>API Keys</h2>
        </div>
        <div class="panel-body">
          <div id="apiKeyEditor"></div>
          <div class="actions">
            <button id="saveApiKeys" class="primary" type="button">Save API keys</button>
          </div>
          <div id="apiKeyNotice" class="notice"></div>
        </div>
      </section>
    </div>
  </main>

  <script>
    const state = {
      modules: [],
      profiles: [],
      roles: [],
      users: [],
      apiKeys: [],
      selectedProfile: "full_recon",
      route: routeFromPath(),
      user: "local",
      userRole: "viewer",
      isAdmin: false,
      canScan: false
    };

    const $ = (id) => document.getElementById(id);

    function routeFromPath() {
      if (location.pathname === "/dashboard") return "dashboard";
      if (location.pathname === "/reports") return "reports";
      if (location.pathname === "/admin" || location.pathname === "/admin/users") return "admin-users";
      if (location.pathname === "/admin/api-keys") return "admin-api-keys";
      if (location.pathname === "/scans") return "scans";
      return "dashboard";
    }

    function setRoute(route, replace = false) {
      state.route = route;
      const paths = {
        "dashboard": "/dashboard",
        "scans": "/scans",
        "reports": "/reports",
        "admin-users": "/admin/users",
        "admin-api-keys": "/admin/api-keys"
      };
      const path = paths[route] || "/dashboard";
      if (location.pathname !== path) {
        history[replace ? "replaceState" : "pushState"]({}, "", path);
      }
      renderRoute();
    }

    function toggleRouteNode(id, visible) {
      const node = $(id);
      if (node) node.classList.toggle("route-hidden", !visible);
    }

    function renderRoute() {
      if (state.route.startsWith("admin-") && !state.isAdmin) {
        setRoute("dashboard", true);
        return;
      }
      $("appLayout").className = `layout route-${state.route}`;
      toggleRouteNode("scanPanel", state.route === "scans");
      toggleRouteNode("metrics", state.route === "dashboard");
      toggleRouteNode("dashboardPanel", state.route === "dashboard");
      toggleRouteNode("jobsPanel", state.route === "scans");
      toggleRouteNode("reportsPanel", state.route === "reports");
      toggleRouteNode("adminPanel", state.route === "admin-users" && state.isAdmin);
      toggleRouteNode("apiKeysPanel", state.route === "admin-api-keys" && state.isAdmin);
      document.querySelectorAll("[data-route-link]").forEach((node) => {
        const adminOnly = node.dataset.adminOnly === "true";
        node.style.display = adminOnly && !state.isAdmin ? "none" : "inline-flex";
        node.classList.toggle("active", node.dataset.routeLink === state.route);
      });
    }

    function showNotice(message) {
      setNotice("notice", message);
    }

    function showAdminNotice(message) {
      setNotice("adminNotice", message);
    }

    function showApiKeyNotice(message) {
      setNotice("apiKeyNotice", message);
    }

    function setNotice(id, message) {
      const node = $(id);
      node.textContent = message || "";
      node.classList.toggle("show", Boolean(message));
    }

    function selectedModules() {
      return [...document.querySelectorAll("[data-module]:checked")].map((node) => Number(node.value));
    }

    function setModules(modules) {
      const selected = new Set(modules);
      document.querySelectorAll("[data-module]").forEach((node) => {
        node.checked = selected.has(Number(node.value));
      });
    }

    function renderApiKeys(keys) {
      const rows = Object.entries(keys || {}).map(([name, on]) => {
        const cls = on ? "on" : "off";
        const label = on ? "set" : "missing";
        return `<span class="api-key ${cls}">${escapeHtml(name)}: ${label}</span>`;
      });
      $("apiKeys").innerHTML = rows.join("");
    }

    function renderUser(user, authMode, role) {
      state.user = user || "local";
      state.userRole = role || "viewer";
      $("userLabel").textContent = `${state.user} (${state.userRole})`;
      document.querySelector(".logout").style.display = authMode === "open" ? "none" : "inline-flex";
    }

    function renderPermissions(canScan) {
      state.canScan = Boolean(canScan);
      $("startScan").disabled = !state.canScan;
      $("startScan").textContent = state.canScan ? "Start customer scan" : "Scanner role required";
    }

    function renderMetrics(jobs, reports, maxWorkers) {
      const running = (jobs || []).filter((job) => job.status === "running").length;
      const queued = (jobs || []).filter((job) => job.status === "queued").length;
      const failed = (jobs || []).filter((job) => job.status === "failed").length;
      const pdfs = (reports || []).filter((report) => report.type === "pdf").length;
      const critical = (reports || []).filter((report) => report.risk_label === "CRITICAL").length;
      $("metrics").innerHTML = [
        { label: "Active Scans", value: running, hint: `${maxWorkers || 1} worker slot(s)` },
        { label: "Queued", value: queued, hint: "Waiting jobs" },
        { label: "PDF Reports", value: pdfs, hint: "Generated customer PDFs" },
        { label: "Critical", value: critical, hint: failed ? `${failed} failed scan(s)` : "Highest risk reports" }
      ].map((item) => (
        `<div class="metric">
          <div class="label">${escapeHtml(item.label)}</div>
          <div class="value">${escapeHtml(item.value)}</div>
          <div class="hint">${escapeHtml(item.hint)}</div>
        </div>`
      )).join("");
    }

    function renderDashboard(jobs, reports) {
      const latestJob = (jobs || [])[0];
      const latestPdfs = (reports || []).filter((report) => report.type === "pdf").slice(0, 6);
      const latestReports = (reports || []).slice(0, 5);
      const latestScanHtml = latestJob ? `
        <div class="overview-main">${escapeHtml(latestJob.domain)}</div>
        <div class="overview-meta">${escapeHtml(latestJob.status)} · ${escapeHtml(latestJob.phase || "No phase")} · by ${escapeHtml(latestJob.created_by || "-")}</div>
        <div class="chip-row">
          <span class="chip">${escapeHtml((latestJob.modules || []).length)} module(s)</span>
          <span class="chip ${latestJob.authorized ? "ok" : "danger"}">${latestJob.authorized ? "authorized" : "authorization missing"}</span>
          ${latestJob.generated_files?.length ? `<span class="chip ok">${latestJob.generated_files.length} file(s)</span>` : ""}
        </div>
      ` : `<div class="empty">No scan jobs yet.</div>`;

      const pdfRows = latestPdfs.length ? latestPdfs.map((report) => `
        <div class="compact-row">
          <div>
            <strong>${escapeHtml(report.domain)}</strong>
            <span>${escapeHtml(report.file)} · ${escapeHtml(formatDate(report.modified))}</span>
          </div>
          <div class="link-actions"><a href="${report.url}" target="_blank" rel="noreferrer">PDF</a></div>
        </div>
      `).join("") : `<div class="empty">No PDFs generated yet.</div>`;

      const reportRows = latestReports.length ? latestReports.map((report) => `
        <div class="compact-row">
          <div>
            <strong>${escapeHtml(report.domain)}</strong>
            <span>${escapeHtml(report.type.toUpperCase())} · risk ${escapeHtml(report.risk_label || "-")} · ${escapeHtml(formatDate(report.modified))}</span>
          </div>
          <div class="link-actions"><a href="${report.url}" target="_blank" rel="noreferrer">${reportActionLabel(report.url)}</a></div>
        </div>
      `).join("") : `<div class="empty">No reports found.</div>`;

      $("dashboardContent").innerHTML = `
        <div class="dashboard-grid">
          <div class="overview-block">
            <h3>Latest Scan</h3>
            ${latestScanHtml}
          </div>
          <div class="overview-block">
            <h3>Latest PDFs</h3>
            <div class="compact-list">${pdfRows}</div>
          </div>
          <div class="overview-block" style="grid-column: 1 / -1">
            <h3>Latest Report Files</h3>
            <div class="compact-list">${reportRows}</div>
          </div>
        </div>`;
    }

    function renderProfiles() {
      $("profiles").innerHTML = state.profiles.map((profile) => (
        `<button type="button" class="profile-btn ${profile.id === state.selectedProfile ? "active" : ""}" data-profile="${profile.id}">
          ${escapeHtml(profile.name)}
        </button>`
      )).join("");
      document.querySelectorAll("[data-profile]").forEach((node) => {
        node.addEventListener("click", () => {
          const profile = state.profiles.find((item) => item.id === node.dataset.profile);
          if (!profile) return;
          state.selectedProfile = profile.id;
          setModules(profile.modules);
          $("exploit").checked = Boolean(profile.exploit);
          renderProfiles();
        });
      });
    }

    function renderModules() {
      $("modules").innerHTML = state.modules.map((module) => (
        `<label class="module ${module.danger ? "danger" : ""}">
          <input data-module type="checkbox" value="${module.id}" ${module.default ? "checked" : ""}>
          <span>
            <span class="module-title">${module.id}. ${escapeHtml(module.name)}</span>
            <span class="module-desc">${escapeHtml(module.description)}</span>
          </span>
        </label>`
      )).join("");
    }

    function renderJobs(jobs) {
      if (!jobs || !jobs.length) {
        $("jobs").innerHTML = `<div class="empty">No scans yet.</div>`;
        return;
      }
      $("jobs").innerHTML = jobs.map((job) => {
        const links = (job.generated_files || []).map((url) => `<a href="${url}" target="_blank" rel="noreferrer">${reportActionLabel(url)}</a>`).join(" ");
        const logs = (job.logs || []).slice(-18).map(escapeHtml).join("\\n");
        const chips = [
          `<span class="chip">by ${escapeHtml(job.created_by || "local")}</span>`,
          `<span class="chip ${job.stealth ? "ok" : ""}">jitter ${job.stealth ? "on" : "off"}</span>`,
          job.exploit ? `<span class="chip danger">exploit on</span>` : `<span class="chip">safe</span>`,
          job.fresh ? `<span class="chip">fresh</span>` : "",
          job.authorized ? `<span class="chip ok">authorized</span>` : `<span class="chip danger">no auth</span>`
        ].filter(Boolean).join("");
        return `<article class="job">
          <div class="job-main">
            <div>
              <h3>${escapeHtml(job.domain)}</h3>
              <div class="job-meta">${escapeHtml(job.phase || "")} &middot; modules ${escapeHtml((job.modules || []).join(", "))}</div>
              <div class="chip-row">${chips}</div>
              ${job.error ? `<div class="job-meta" style="color: var(--red); font-weight: 800">${escapeHtml(job.error)}</div>` : ""}
              ${links ? `<div class="link-actions" style="margin-top:8px">${links}</div>` : ""}
            </div>
            <span class="status ${escapeHtml(job.status)}">${escapeHtml(job.status)}</span>
          </div>
          <div class="progress"><span style="width:${Number(job.progress || 0)}%"></span></div>
          <pre class="logs">${logs}</pre>
        </article>`;
      }).join("");
    }

    function renderReports(reports) {
      if (!reports || !reports.length) {
        $("reports").innerHTML = `<div class="empty">No reports found.</div>`;
        return;
      }
      const rows = reports.map((report) => {
        const risk = report.risk_label || "-";
        const when = formatDate(report.scan_date || report.modified);
        const action = report.type === "html" ? "HTML" : report.type === "pdf" ? "PDF" : "JSON";
        return `<tr>
          <td><strong>${escapeHtml(report.domain)}</strong><br><span class="job-meta">${escapeHtml(report.file)}</span></td>
          <td><span class="risk ${escapeHtml(risk)}">${escapeHtml(risk)}</span></td>
          <td>${escapeHtml(report.findings ?? "-")}</td>
          <td>${escapeHtml(when)}</td>
          <td><div class="link-actions"><a href="${report.url}" target="_blank" rel="noreferrer">${action}</a></div></td>
        </tr>`;
      }).join("");
      $("reports").innerHTML = `<table class="reports">
        <thead><tr><th>Target</th><th>Risk</th><th>Findings</th><th>Date</th><th>Open</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    function reportActionLabel(url) {
      if (String(url).endsWith(".html")) return "HTML";
      if (String(url).endsWith(".pdf")) return "PDF";
      return "JSON";
    }

    function renderAdminRoles() {
      $("adminRole").innerHTML = (state.roles || []).map((role) => (
        `<option value="${escapeHtml(role.id)}">${escapeHtml(role.label)}</option>`
      )).join("");
    }

    function renderAdminPanel(isAdmin, users, roles) {
      state.isAdmin = Boolean(isAdmin);
      state.users = users || [];
      state.roles = roles || [];
      $("adminPanel").hidden = false;
      $("apiKeysPanel").hidden = false;
      if (!state.isAdmin) return;
      renderAdminRoles();
      renderUsers();
    }

    function renderApiKeyEditor(apiKeys) {
      state.apiKeys = apiKeys || [];
      if (!state.isAdmin) return;
      if (!state.apiKeys.length) {
        $("apiKeyEditor").innerHTML = `<div class="empty">No API key definitions found.</div>`;
        return;
      }
      $("apiKeyEditor").innerHTML = `<div class="key-list">${state.apiKeys.map((key) => `
        <div class="key-row">
          <div>
            <h3>${escapeHtml(key.label)}</h3>
            <p>${escapeHtml(key.description)}</p>
            <code>${escapeHtml(key.env)}${key.masked ? ` · ${escapeHtml(key.masked)}` : ""}</code>
          </div>
          <div class="key-controls">
            <input data-api-key="${escapeHtml(key.env)}" type="password" placeholder="${key.configured ? "leave blank to keep current key" : "paste API key"}" autocomplete="off">
            <label class="key-clear">
              <input data-api-clear="${escapeHtml(key.env)}" type="checkbox">
              Clear saved value
            </label>
          </div>
          <span class="key-status ${key.configured ? "on" : ""}">${key.configured ? "configured" : "missing"}</span>
        </div>
      `).join("")}</div>`;
    }

    function renderUsers() {
      if (!state.users.length) {
        $("users").innerHTML = `<div class="empty">No managed users yet.</div>`;
        return;
      }
      const rows = state.users.map((user) => (
        `<tr>
          <td><strong>${escapeHtml(user.username)}</strong><br><span class="job-meta">${escapeHtml(user.source || "local")}</span></td>
          <td><span class="chip ${user.role === "admin" ? "ok" : ""}">${escapeHtml(user.role)}</span></td>
          <td>${user.active ? '<span class="chip ok">active</span>' : '<span class="chip danger">disabled</span>'}</td>
          <td>${escapeHtml(formatDate(user.updated_at || user.created_at))}</td>
          <td>
            <div class="link-actions">
              <button class="secondary" type="button" data-edit-user="${escapeHtml(user.username)}">Edit</button>
              <button class="secondary" type="button" data-delete-user="${escapeHtml(user.username)}">Delete</button>
            </div>
          </td>
        </tr>`
      )).join("");
      $("users").innerHTML = `<table class="users-table">
        <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Updated</th><th>Actions</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
      document.querySelectorAll("[data-edit-user]").forEach((node) => {
        node.addEventListener("click", () => fillUserForm(node.dataset.editUser));
      });
      document.querySelectorAll("[data-delete-user]").forEach((node) => {
        node.addEventListener("click", () => deleteUser(node.dataset.deleteUser));
      });
    }

    function fillUserForm(username) {
      const user = state.users.find((item) => item.username === username);
      if (!user) return;
      $("adminUsername").value = user.username;
      $("adminPassword").value = "";
      $("adminRole").value = user.role;
      $("adminActive").checked = Boolean(user.active);
      showAdminNotice("");
    }

    async function load() {
      const response = await fetch("/api/bootstrap", { cache: "no-store" });
      if (!response.ok) {
        if (response.status === 401) location.reload();
        return;
      }
      const data = await response.json();
      if (!state.modules.length) {
        state.modules = data.modules || [];
        state.profiles = data.profiles || [];
        renderModules();
        renderProfiles();
      }
      renderUser(data.user, data.auth_mode, data.user_role);
      renderPermissions(data.can_scan);
      renderApiKeys(data.api_keys);
      renderJobs(data.jobs);
      renderReports(data.reports);
      renderMetrics(data.jobs, data.reports, data.max_workers);
      renderDashboard(data.jobs, data.reports);
      renderAdminPanel(data.is_admin, data.users, data.roles);
      renderApiKeyEditor(data.api_key_status || []);
      renderRoute();
    }

    async function startScan() {
      showNotice("");
      if (!state.canScan) {
        showNotice("Your user role cannot start scans.");
        return;
      }
      const modules = selectedModules();
      const payload = {
        domain: $("domain").value.trim(),
        modules,
        stealth: $("stealth").checked,
        exploit: $("exploit").checked,
        fresh: $("fresh").checked,
        authorized: $("authorized").checked
      };
      if (!payload.authorized) {
        showNotice("Confirm customer authorization before starting the scan.");
        return;
      }
      if (modules.includes(11) && !payload.exploit) {
        showNotice("Module 11 needs exploit mode.");
        return;
      }
      $("startScan").disabled = true;
      try {
        const response = await fetch("/api/scans", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Scan could not be started.");
        $("domain").value = "";
        $("authorized").checked = false;
        await load();
      } catch (error) {
        showNotice(error.message);
      } finally {
        $("startScan").disabled = !state.canScan;
      }
    }

    async function saveUser() {
      showAdminNotice("");
      const payload = {
        username: $("adminUsername").value.trim(),
        password: $("adminPassword").value,
        role: $("adminRole").value,
        active: $("adminActive").checked
      };
      $("saveUser").disabled = true;
      try {
        const response = await fetch("/api/users", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "User could not be saved.");
        $("adminPassword").value = "";
        await load();
      } catch (error) {
        showAdminNotice(error.message);
      } finally {
        $("saveUser").disabled = false;
      }
    }

    async function deleteUser(username) {
      showAdminNotice("");
      if (!confirm(`Delete user ${username}?`)) return;
      try {
        const response = await fetch(`/api/users/${encodeURIComponent(username)}`, { method: "DELETE" });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "User could not be deleted.");
        await load();
      } catch (error) {
        showAdminNotice(error.message);
      }
    }

    async function saveApiKeys() {
      showApiKeyNotice("");
      const values = {};
      const clear = [];
      document.querySelectorAll("[data-api-key]").forEach((node) => {
        const value = node.value.trim();
        if (value) values[node.dataset.apiKey] = value;
      });
      document.querySelectorAll("[data-api-clear]:checked").forEach((node) => {
        clear.push(node.dataset.apiClear);
      });
      if (!Object.keys(values).length && !clear.length) {
        showApiKeyNotice("No API key changes to save.");
        return;
      }
      $("saveApiKeys").disabled = true;
      try {
        const response = await fetch("/api/admin/api-keys", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ values, clear })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "API keys could not be saved.");
        state.apiKeys = data.api_keys || [];
        renderApiKeyEditor(state.apiKeys);
        showApiKeyNotice("API keys saved.");
        await load();
      } catch (error) {
        showApiKeyNotice(error.message);
      } finally {
        $("saveApiKeys").disabled = false;
      }
    }

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
      }[char]));
    }

    function formatDate(value) {
      if (!value) return "-";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString();
    }

    $("startScan").addEventListener("click", startScan);
    $("saveUser").addEventListener("click", saveUser);
    $("saveApiKeys").addEventListener("click", saveApiKeys);
    document.querySelectorAll("[data-route-link]").forEach((node) => {
      node.addEventListener("click", (event) => {
        event.preventDefault();
        setRoute(node.dataset.routeLink || "scans");
      });
    });
    window.addEventListener("popstate", () => {
      state.route = routeFromPath();
      renderRoute();
    });
    $("refresh").addEventListener("click", load);
    $("selectSafe").addEventListener("click", () => {
      const profile = state.profiles.find((item) => item.id === "full_recon");
      if (profile) {
        state.selectedProfile = profile.id;
        setModules(profile.modules);
        $("exploit").checked = false;
        renderProfiles();
      }
    });
    $("exploit").addEventListener("change", () => {
      const module11 = document.querySelector('[data-module][value="11"]');
      if (module11 && $("exploit").checked) module11.checked = true;
    });

    load();
    setInterval(load, 5000);
  </script>
</body>
</html>"""


def local_ip_hint() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def port_available(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
        return True
    except OSError:
        return False


def next_available_port(host: str, start_port: int) -> int:
    for port in range(start_port, start_port + 100):
        if port_available(host, port):
            return port
    raise OSError(f"No free port found between {start_port} and {start_port + 99}.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the link-ed.it CyberScan web console.")
    parser.add_argument("--host", default=os.environ.get("EASM_WEB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    explicit_port = args.port is not None or "EASM_WEB_PORT" in os.environ
    port = args.port if args.port is not None else DEFAULT_WEB_PORT

    try:
        server = ThreadingHTTPServer((args.host, port), WebHandler)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE and not explicit_port:
            fallback_port = next_available_port(args.host, port + 1)
            print(f"Port {port} is already in use. Using free port {fallback_port} instead.")
            port = fallback_port
            server = ThreadingHTTPServer((args.host, port), WebHandler)
        elif exc.errno == errno.EADDRINUSE:
            print(f"Port {port} is already in use.")
            print(f"Try: python web_app.py --port {port + 1}")
            raise SystemExit(1) from exc
        else:
            raise

    shown_host = "127.0.0.1" if args.host == "0.0.0.0" else args.host
    print(f"link-ed.it CyberScan running at http://{shown_host}:{port}")
    if args.host == "0.0.0.0":
        lan_ip = local_ip_hint()
        if lan_ip:
            print(f"LAN URL: http://{lan_ip}:{port}")
    if has_managed_users():
        print(f"Managed team login enabled for {len(list_managed_users())} user(s) via {USERS_FILE}.")
    elif WEB_USERS:
        print(f"Team login enabled for {len(WEB_USERS)} user(s) via EASM_WEB_USERS.")
    elif WEB_TOKEN:
        print("Shared token login enabled via EASM_WEB_TOKEN.")
    else:
        print("Initial admin setup required at /setup before employees can use the portal.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping web console.")
    finally:
        EXECUTOR.shutdown(wait=False, cancel_futures=False)
        server.server_close()


if __name__ == "__main__":
    main()
