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
import io
import json
import mimetypes
import os
import re
import secrets
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

import config
from checkpoint import Checkpoint
from html_report import calculate_risk_score, extract_findings
from main import MODULE_REGISTRY, RESULT_KEYS, run_module
from report import ReportGenerator
from state_manager import StateTracker


BASE_DIR = Path(__file__).resolve().parent
VENDOR_DIR = BASE_DIR / "vendor"
if VENDOR_DIR.is_dir() and str(VENDOR_DIR) not in sys.path:
    sys.path.insert(0, str(VENDOR_DIR))
DATA_DIR = Path(os.environ.get("EASM_DATA_DIR", str(BASE_DIR))).resolve()
RESULTS_DIR = Path(os.environ.get("EASM_RESULTS_DIR", str(DATA_DIR / "results"))).resolve()
APP_TITLE = "link-ed.it CyberScan"
APP_TAGLINE = "Internal customer-domain security scans"
COMPANY_NAME = "link-ed.it"
USERS_FILE = Path(os.environ.get("EASM_WEB_USERS_FILE", str(DATA_DIR / "web_users.json"))).resolve()
STATE_DB = Path(os.environ.get("EASM_STATE_DB", str(DATA_DIR / "easm_state.db"))).resolve()
SCHEDULE_FILE = Path(os.environ.get("EASM_SCAN_SCHEDULE_FILE", str(DATA_DIR / "scan_schedule.json"))).resolve()
WEB_TOKEN = os.environ.get("EASM_WEB_TOKEN", "").strip()
WEB_USERS_RAW = os.environ.get("EASM_WEB_USERS", "").strip()
SESSION_COOKIE = "easm_session"
TRUSTED_2FA_COOKIE = "easm_trusted_2fa"
SESSION_TTL_SECONDS = int(os.environ.get("EASM_WEB_SESSION_SECONDS", "43200"))
TWO_FACTOR_CHALLENGE_SECONDS = int(os.environ.get("EASM_2FA_CHALLENGE_SECONDS", "600"))
TRUSTED_2FA_SECONDS = int(os.environ.get("EASM_TRUSTED_2FA_SECONDS", str(30 * 24 * 60 * 60)))
SESSION_SECRET = (
    os.environ.get("EASM_WEB_SESSION_SECRET")
    or WEB_TOKEN
    or secrets.token_hex(32)
).encode("utf-8")
DEFAULT_WEB_PORT = int(os.environ.get("EASM_WEB_PORT", "18080"))
MAX_WORKERS = int(os.environ.get("EASM_WEB_MAX_WORKERS", "1"))
SCHEDULE_POLL_SECONDS = int(os.environ.get("EASM_SCHEDULE_POLL_SECONDS", "300"))
USER_ROLES = [
    {"id": "admin", "label": "Admin"},
    {"id": "scanner", "label": "Scanner"},
    {"id": "viewer", "label": "Viewer"},
]
ROLE_IDS = {role["id"] for role in USER_ROLES}
USER_LOCK = threading.RLock()
SCHEDULE_LOCK = threading.RLock()
SCHEDULER_STOP = threading.Event()
ENV_FILE = Path(
    os.environ.get(
        "EASM_ENV_FILE",
        str(DATA_DIR / ".env" if "EASM_DATA_DIR" in os.environ else BASE_DIR / ".env"),
    )
).resolve()

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


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def profile_by_id(profile_id: str) -> dict[str, Any] | None:
    for profile in PROFILES:
        if profile["id"] == profile_id:
            return profile
    return None


def parse_cadence_days(value: Any) -> int:
    try:
        days = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Schedule cadence must be a number of days.") from exc
    if days < 1 or days > 365:
        raise ValueError("Schedule cadence must be between 1 and 365 days.")
    return days


def parse_schedule_date(value: Any) -> date:
    if not value:
        return datetime.now(timezone.utc).date()
    text = str(value).strip()
    if "T" in text:
        text = text.split("T", 1)[0]
    try:
        return date.fromisoformat(text[:10])
    except ValueError as exc:
        raise ValueError("Next scan date must use YYYY-MM-DD.") from exc


def normalize_schedule_payload(
    payload: dict[str, Any],
    username: str,
    existing: dict[str, Any] | None = None,
    touch: bool = True,
) -> dict[str, Any]:
    existing = existing or {}
    domain = validate_domain(str(payload.get("domain", existing.get("domain", ""))))
    profile_id = str(payload.get("profile", existing.get("profile", "full_recon")) or "full_recon").strip()
    profile = profile_by_id(profile_id)
    if not profile:
        raise ValueError("Unknown scan profile.")

    modules_raw = payload.get("modules", existing.get("modules", profile["modules"]))
    modules = parse_modules(modules_raw)
    exploit = parse_bool(payload.get("exploit", existing.get("exploit", profile.get("exploit", False))))
    if exploit and 11 not in modules:
        modules = sorted(set(modules + [11]))
    if 11 in modules and not exploit:
        raise ValueError("Module 11 schedules require exploit mode.")

    active = parse_bool(payload.get("active", existing.get("active", True)), True)
    authorized = parse_bool(payload.get("authorized", existing.get("authorized", False)))
    if active and not authorized:
        raise ValueError("Confirm customer authorization before saving an active schedule.")

    cadence_raw = payload.get("cadence_days", payload.get("cadence", existing.get("cadence_days", 30)))
    next_raw = payload.get("next_scan", existing.get("next_scan", datetime.now(timezone.utc).date().isoformat()))
    created_at = str(existing.get("created_at") or utc_now())
    created_by = str(existing.get("created_by") or username)

    return {
        "id": str(payload.get("id", existing.get("id") or secrets.token_hex(6))),
        "domain": domain,
        "profile": profile_id,
        "profile_name": profile["name"],
        "modules": modules,
        "stealth": parse_bool(payload.get("stealth", existing.get("stealth", True)), True),
        "exploit": exploit,
        "fresh": parse_bool(payload.get("fresh", existing.get("fresh", True)), True),
        "authorized": authorized,
        "active": active,
        "cadence_days": parse_cadence_days(cadence_raw),
        "next_scan": parse_schedule_date(next_raw).isoformat(),
        "created_by": created_by,
        "created_at": created_at,
        "updated_by": username if touch else str(existing.get("updated_by") or username),
        "updated_at": utc_now() if touch else str(existing.get("updated_at") or created_at),
        "last_queued_at": str(payload.get("last_queued_at", existing.get("last_queued_at", "")) or ""),
    }


def _read_schedule_unlocked() -> list[dict[str, Any]]:
    if not SCHEDULE_FILE.exists():
        return []
    try:
        with SCHEDULE_FILE.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []
    raw_items = data.get("items", []) if isinstance(data, dict) else data
    if not isinstance(raw_items, list):
        return []

    items: list[dict[str, Any]] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            continue
        try:
            items.append(normalize_schedule_payload(
                raw,
                str(raw.get("updated_by") or raw.get("created_by") or "system"),
                raw,
                touch=False,
            ))
        except Exception:
            continue
    return items


def _write_schedule_unlocked(items: list[dict[str, Any]]) -> None:
    SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = SCHEDULE_FILE.with_suffix(SCHEDULE_FILE.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump({"items": items}, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    tmp_path.replace(SCHEDULE_FILE)


def latest_report_by_domain(reports: list[dict[str, Any]]) -> dict[str, str]:
    latest: dict[str, str] = {}
    for report in reports:
        domain = str(report.get("domain", "") or "")
        stamp = str(report.get("scan_date") or report.get("modified") or "")
        if not domain or not stamp:
            continue
        if stamp > latest.get(domain, ""):
            latest[domain] = stamp
    return latest


def active_job_status_by_domain(jobs: list[dict[str, Any]]) -> dict[str, str]:
    status_rank = {"running": 0, "queued": 1}
    active: dict[str, str] = {}
    for job in jobs:
        status = str(job.get("status", "") or "")
        if status not in status_rank:
            continue
        domain = str(job.get("domain", "") or "")
        if not domain:
            continue
        current = active.get(domain)
        if current is None or status_rank[status] < status_rank[current]:
            active[domain] = status
    return active


def decorate_schedule_item(
    item: dict[str, Any],
    jobs: list[dict[str, Any]],
    reports: list[dict[str, Any]],
) -> dict[str, Any]:
    today = datetime.now(timezone.utc).date()
    next_date = parse_schedule_date(item.get("next_scan"))
    days_until = (next_date - today).days
    active_jobs = active_job_status_by_domain(jobs)
    latest_reports = latest_report_by_domain(reports)
    active = bool(item.get("active", True))

    if not active:
        due_state = "disabled"
    elif days_until < 0:
        due_state = "overdue"
    elif days_until == 0:
        due_state = "due_today"
    elif days_until <= 7:
        due_state = "due_soon"
    else:
        due_state = "scheduled"

    domain = str(item.get("domain", ""))
    active_job = active_jobs.get(domain, "")
    last_scan_date = latest_reports.get(domain, "")
    decorated = dict(item)
    decorated.update({
        "days_until": days_until,
        "due_state": due_state,
        "last_scan_date": last_scan_date,
        "active_job_status": active_job,
        "needs_scan": bool(active and not active_job and (days_until <= 0 or not last_scan_date)),
    })
    return decorated


def list_scan_schedule(
    jobs: list[dict[str, Any]] | None = None,
    reports: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    jobs = JOBS.list() if jobs is None else jobs
    reports = list_reports() if reports is None else reports
    with SCHEDULE_LOCK:
        items = _read_schedule_unlocked()
    decorated = [decorate_schedule_item(item, jobs, reports) for item in items]
    return sorted(decorated, key=lambda item: (not item.get("active", True), item.get("days_until", 9999), item.get("domain", "")))


def scan_overview(
    schedule: list[dict[str, Any]] | None = None,
    jobs: list[dict[str, Any]] | None = None,
    reports: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    jobs = JOBS.list() if jobs is None else jobs
    reports = list_reports() if reports is None else reports
    schedule = list_scan_schedule(jobs, reports) if schedule is None else schedule
    active_items = [item for item in schedule if item.get("active", True)]
    report_domains = {str(report.get("domain", "")) for report in reports if report.get("domain")}
    scheduled_domains = {str(item.get("domain", "")) for item in active_items if item.get("domain")}
    due_items = [item for item in active_items if int(item.get("days_until", 9999)) <= 0]
    next_due = next((item for item in active_items if int(item.get("days_until", 9999)) >= 0), None)

    return {
        "running": sum(1 for job in jobs if job.get("status") == "running"),
        "queued": sum(1 for job in jobs if job.get("status") == "queued"),
        "scheduled_total": len(schedule),
        "scheduled_active": len(active_items),
        "due_now": len(due_items),
        "overdue": sum(1 for item in active_items if item.get("due_state") == "overdue"),
        "due_this_week": sum(1 for item in active_items if 0 <= int(item.get("days_until", 9999)) <= 7),
        "never_scanned": sum(1 for item in active_items if not item.get("last_scan_date")),
        "needs_scan": sum(1 for item in active_items if item.get("needs_scan")),
        "coverage_domains": len(scheduled_domains | report_domains),
        "scheduled_domains": len(scheduled_domains),
        "reported_domains": len(report_domains),
        "next_due_domain": next_due.get("domain", "") if next_due else "",
        "next_due_date": next_due.get("next_scan", "") if next_due else "",
    }


def upsert_scan_schedule(payload: dict[str, Any], username: str) -> dict[str, Any]:
    with SCHEDULE_LOCK:
        items = _read_schedule_unlocked()
        schedule_id = str(payload.get("id", "") or "")
        existing_index = next((idx for idx, item in enumerate(items) if item.get("id") == schedule_id), None)
        existing = items[existing_index] if existing_index is not None else None
        item = normalize_schedule_payload(payload, username, existing)
        if existing_index is None:
            items.append(item)
        else:
            items[existing_index] = item
        _write_schedule_unlocked(items)
    return item


def delete_scan_schedule(schedule_id: str) -> bool:
    with SCHEDULE_LOCK:
        items = _read_schedule_unlocked()
        kept = [item for item in items if item.get("id") != schedule_id]
        if len(kept) == len(items):
            return False
        _write_schedule_unlocked(kept)
        return True


def get_scan_schedule(schedule_id: str) -> dict[str, Any] | None:
    with SCHEDULE_LOCK:
        for item in _read_schedule_unlocked():
            if item.get("id") == schedule_id:
                return item
    return None


def mark_schedule_queued(schedule_id: str, username: str) -> dict[str, Any] | None:
    with SCHEDULE_LOCK:
        items = _read_schedule_unlocked()
        for index, item in enumerate(items):
            if item.get("id") != schedule_id:
                continue
            next_date = datetime.now(timezone.utc).date() + timedelta(days=int(item.get("cadence_days", 30)))
            updated = dict(item)
            updated.update({
                "next_scan": next_date.isoformat(),
                "last_queued_at": utc_now(),
                "updated_by": username,
                "updated_at": utc_now(),
            })
            items[index] = updated
            _write_schedule_unlocked(items)
            return updated
    return None


def queue_schedule_job(item: dict[str, Any], username: str, source: str = "schedule") -> ScanJob:
    if not item.get("authorized"):
        raise ValueError("Customer authorization is required before this scheduled scan can run.")
    if 11 in item.get("modules", []) and not item.get("exploit"):
        raise ValueError("Module 11 schedules require exploit mode.")
    job = JOBS.create(
        str(item["domain"]),
        list(item["modules"]),
        bool(item.get("stealth", True)),
        bool(item.get("exploit", False)),
        bool(item.get("fresh", True)),
        True,
        username,
    )
    job.log(f"Queued from {source} by {username}.")
    EXECUTOR.submit(run_scan_job, job)
    mark_schedule_queued(str(item["id"]), username)
    return job


def run_due_schedules_once() -> int:
    jobs = JOBS.list()
    reports = list_reports()
    schedule = list_scan_schedule(jobs, reports)
    queued = 0
    for item in schedule:
        if not item.get("active", True):
            continue
        if int(item.get("days_until", 9999)) > 0:
            continue
        if item.get("active_job_status"):
            continue
        if not item.get("authorized"):
            continue
        try:
            queue_schedule_job(item, "scheduler", "automatic schedule")
            queued += 1
        except Exception as exc:
            print(f"[scheduler] Could not queue {item.get('domain', '-')}: {exc}")
    return queued


def schedule_loop() -> None:
    while not SCHEDULER_STOP.is_set():
        try:
            queued = run_due_schedules_once()
            if queued:
                print(f"[scheduler] Queued {queued} due scheduled scan(s).")
        except Exception as exc:
            print(f"[scheduler] Schedule poll failed: {exc}")
        SCHEDULER_STOP.wait(max(30, SCHEDULE_POLL_SECONDS))


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


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def format_totp_secret(secret: str) -> str:
    clean = re.sub(r"[^A-Z2-7]", "", (secret or "").upper())
    return " ".join(clean[index:index + 4] for index in range(0, len(clean), 4))


def decode_totp_secret(secret: str) -> bytes:
    clean = re.sub(r"[^A-Z2-7]", "", (secret or "").upper())
    if not clean:
        raise ValueError("Missing authenticator secret.")
    return base64.b32decode(clean + "=" * (-len(clean) % 8), casefold=True)


def totp_code(secret: str, counter: int, digits: int = 6) -> str:
    key = decode_totp_secret(secret)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    clean = re.sub(r"\D", "", code or "")
    if len(clean) != 6:
        return False
    counter = int(time.time() // 30)
    for drift in range(-window, window + 1):
        try:
            expected = totp_code(secret, counter + drift)
        except Exception:
            return False
        if secrets.compare_digest(expected, clean):
            return True
    return False


def two_factor_enabled(user: dict[str, Any] | None) -> bool:
    return bool(user and user.get("totp_enabled") and user.get("totp_secret"))


def two_factor_required_for_user(username: str) -> bool:
    return bool(has_managed_users() and get_managed_user(username))


def totp_fingerprint(user: dict[str, Any]) -> str:
    secret = str(user.get("totp_secret", "") or "")
    reset = str(user.get("totp_reset_at", "") or "")
    return hashlib.sha256(f"{secret}:{reset}".encode("utf-8")).hexdigest()[:24]


def otpauth_uri(username: str, secret: str) -> str:
    issuer = APP_TITLE
    label = f"{COMPANY_NAME}:{username}"
    return (
        f"otpauth://totp/{quote(label)}"
        f"?secret={quote(secret)}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )


def qr_data_uri(value: str) -> str:
    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
    except Exception:
        return ""
    image = qrcode.make(value, image_factory=SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    return "data:image/svg+xml;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


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
        "two_factor_enabled": two_factor_enabled(user),
        "two_factor_pending": bool(user.get("totp_pending_secret")),
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
    if existing:
        for key in (
            "totp_enabled",
            "totp_secret",
            "totp_created_at",
            "totp_pending_secret",
            "totp_pending_at",
            "totp_reset_at",
        ):
            if key in existing:
                record[key] = existing[key]
    if password:
        record["password"] = hash_password(password)

    users[username] = record
    if _active_admin_count(data) < 1:
        raise ValueError("At least one active admin user is required.")
    save_user_store(data)
    return sanitize_user(username, record)


def reset_user_two_factor(username: str, updated_by: str) -> dict[str, Any]:
    username = (username or "").strip()
    data = load_user_store()
    users = data.get("users", {})
    user = users.get(username)
    if not isinstance(user, dict):
        raise ValueError("User not found.")
    for key in ("totp_enabled", "totp_secret", "totp_created_at", "totp_pending_secret", "totp_pending_at"):
        user.pop(key, None)
    user["totp_reset_at"] = utc_now()
    user["updated_at"] = utc_now()
    user["updated_by"] = updated_by
    save_user_store(data)
    return sanitize_user(username, user)


def begin_two_factor_enrollment(username: str) -> dict[str, Any]:
    username = (username or "").strip()
    data = load_user_store()
    users = data.get("users", {})
    user = users.get(username)
    if not isinstance(user, dict) or not user.get("active", True):
        raise ValueError("User not found.")
    if two_factor_enabled(user):
        secret = str(user["totp_secret"])
    else:
        secret = str(user.get("totp_pending_secret") or generate_totp_secret())
        user["totp_pending_secret"] = secret
        user["totp_pending_at"] = utc_now()
        save_user_store(data)
    uri = otpauth_uri(username, secret)
    return {
        "purpose": "enroll",
        "username": username,
        "challenge": sign_two_factor_challenge(username, "enroll"),
        "secret": secret,
        "formatted_secret": format_totp_secret(secret),
        "otpauth_uri": uri,
        "qr_data_uri": qr_data_uri(uri),
    }


def two_factor_verify_context(username: str) -> dict[str, Any]:
    return {
        "purpose": "verify",
        "username": username,
        "challenge": sign_two_factor_challenge(username, "verify"),
    }


def confirm_two_factor_enrollment(username: str, code: str) -> dict[str, Any]:
    username = (username or "").strip()
    data = load_user_store()
    users = data.get("users", {})
    user = users.get(username)
    if not isinstance(user, dict) or not user.get("active", True):
        raise ValueError("User not found.")
    secret = str(user.get("totp_pending_secret") or user.get("totp_secret") or "")
    if not verify_totp_code(secret, code):
        raise ValueError("Invalid authenticator code.")
    user["totp_enabled"] = True
    user["totp_secret"] = secret
    user["totp_created_at"] = utc_now()
    user.pop("totp_pending_secret", None)
    user.pop("totp_pending_at", None)
    user["updated_at"] = utc_now()
    user["updated_by"] = username
    save_user_store(data)
    return user


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


def sign_token(payload: dict[str, Any]) -> str:
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(SESSION_SECRET, payload_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_b64}.{b64url(sig)}"


def verify_signed_token(value: str, expected_type: str) -> dict[str, Any] | None:
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
    if payload.get("typ") != expected_type:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload if isinstance(payload, dict) else None


def sign_session(username: str) -> str:
    payload = {
        "typ": "session",
        "user": username,
        "exp": int(time.time()) + SESSION_TTL_SECONDS,
    }
    return sign_token(payload)


def verify_session(value: str) -> str | None:
    payload = verify_signed_token(value, "session")
    if not payload:
        return None
    username = str(payload.get("user", "")).strip()
    return username or None


def sign_two_factor_challenge(username: str, purpose: str) -> str:
    return sign_token({
        "typ": "2fa_challenge",
        "user": username,
        "purpose": purpose,
        "nonce": secrets.token_hex(8),
        "exp": int(time.time()) + TWO_FACTOR_CHALLENGE_SECONDS,
    })


def verify_two_factor_challenge(value: str) -> dict[str, Any] | None:
    payload = verify_signed_token(value, "2fa_challenge")
    if not payload:
        return None
    username = str(payload.get("user", "")).strip()
    purpose = str(payload.get("purpose", "")).strip()
    if not username or purpose not in {"enroll", "verify"}:
        return None
    return payload


def sign_trusted_device(username: str, user: dict[str, Any]) -> str:
    return sign_token({
        "typ": "trusted_2fa",
        "user": username,
        "fp": totp_fingerprint(user),
        "exp": int(time.time()) + TRUSTED_2FA_SECONDS,
    })


def verify_trusted_device(value: str, username: str, user: dict[str, Any]) -> bool:
    payload = verify_signed_token(value, "trusted_2fa")
    if not payload:
        return False
    if str(payload.get("user", "")) != username:
        return False
    return secrets.compare_digest(str(payload.get("fp", "")), totp_fingerprint(user))


def cookie_header(name: str, value: str, max_age: int, http_only: bool = True) -> str:
    parts = [f"{name}={value}", f"Max-Age={max_age}", "SameSite=Lax", "Path=/"]
    if http_only:
        parts.insert(2, "HttpOnly")
    return "; ".join(parts)


def session_cookie_header(username: str) -> str:
    return cookie_header(SESSION_COOKIE, sign_session(username), SESSION_TTL_SECONDS)


def clear_cookie_header(name: str) -> str:
    return cookie_header(name, "", 0)


def login_headers(username: str, trust_device: bool = False, user: dict[str, Any] | None = None) -> list[tuple[str, str]]:
    headers = [
        ("Set-Cookie", session_cookie_header(username)),
        ("Location", "/dashboard"),
    ]
    if trust_device and user and two_factor_enabled(user):
        headers.insert(1, ("Set-Cookie", cookie_header(
            TRUSTED_2FA_COOKIE,
            sign_trusted_device(username, user),
            TRUSTED_2FA_SECONDS,
        )))
    return headers


def public_path(path: Path) -> str:
    rel = path.resolve().relative_to(RESULTS_DIR.resolve())
    return "/reports/" + "/".join(rel.parts)


def public_download_path(path: Path) -> str:
    return f"{public_path(path)}?download=1"


def attachment_headers(path: Path) -> dict[str, str]:
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", path.name).strip("._") or "report"
    return {"Content-Disposition": f'attachment; filename="{safe_name}"'}


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
        "download_url": public_download_path(path),
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
        if path.is_file() and path.name != "checkpoint.json" and path.suffix.lower() in {".json", ".html", ".pdf"}:
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
            tracker = StateTracker(str(STATE_DB))
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
    jobs = JOBS.list()
    reports = list_reports()
    schedule = list_scan_schedule(jobs, reports)
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
        "jobs": jobs,
        "reports": reports,
        "schedule": schedule,
        "scan_overview": scan_overview(schedule, jobs, reports),
    }


class WebHandler(BaseHTTPRequestHandler):
    server_version = "LinkedItCyberScan/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[web] {self.address_string()} - {fmt % args}")

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8",
              headers: dict[str, str] | list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            header_items = headers.items() if isinstance(headers, dict) else headers
            for key, value in header_items:
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

    def _cookie_value(self, name: str) -> str:
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = jar.get(name)
        return morsel.value if morsel else ""

    def _current_user(self) -> str | None:
        if not auth_required():
            return "local"
        session_value = self._cookie_value(SESSION_COOKIE)
        if session_value:
            username = verify_session(session_value)
            if username:
                if has_managed_users():
                    managed = get_managed_user(username)
                    if managed and managed.get("active", True) and two_factor_enabled(managed):
                        return username
                elif username in WEB_USERS or not WEB_USERS:
                    return username

        legacy = self._cookie_value("easm_token")
        if legacy and WEB_TOKEN and secrets.compare_digest(legacy, WEB_TOKEN):
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
        if path.startswith("/static/"):
            try:
                asset_path = safe_static_path(path)
            except FileNotFoundError:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
                return
            content_type = mimetypes.guess_type(str(asset_path))[0] or "application/octet-stream"
            self._send(200, asset_path.read_bytes(), content_type)
            return
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
                [
                    ("Set-Cookie", clear_cookie_header(SESSION_COOKIE)),
                    ("Location", "/login"),
                ],
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
        if path in {"/admin/users", "/admin/api-keys"} and not is_admin_user(self._current_user() or ""):
            self._send(303, b"", "text/plain; charset=utf-8", {"Location": "/dashboard"})
            return
        if path in APP_ROUTES:
            self._send(200, render_app_page(path).encode("utf-8"))
            return
        if path == "/api/bootstrap":
            self._json(200, app_bootstrap(self._current_user() or "local"))
            return
        if path == "/api/scans":
            self._json(200, {"jobs": JOBS.list()})
            return
        if path == "/api/schedule":
            jobs = JOBS.list()
            reports = list_reports()
            schedule = list_scan_schedule(jobs, reports)
            self._json(200, {"schedule": schedule, "overview": scan_overview(schedule, jobs, reports)})
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
            query = parse_qs(urlsplit(self.path).query)
            headers = attachment_headers(report_path) if "download" in query else None
            self._send(200, report_path.read_bytes(), content_type, headers)
            return
        self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:
        path = urlsplit(self.path).path
        if path.startswith("/static/"):
            try:
                asset_path = safe_static_path(path)
            except FileNotFoundError:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            content_type = mimetypes.guess_type(str(asset_path))[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(asset_path.stat().st_size))
            self.end_headers()
            return
        if path == "/setup":
            if setup_required():
                body = render_setup().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
            else:
                self.send_response(303)
                self.send_header("Location", "/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
            return
        if path == "/login":
            body = (render_setup() if setup_required() else render_login()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
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
        if path in {"/admin/users", "/admin/api-keys"} and not is_admin_user(self._current_user() or ""):
            self.send_response(303)
            self.send_header("Location", "/dashboard")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path in APP_ROUTES:
            body = render_app_page(path).encode("utf-8")
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
            query = parse_qs(urlsplit(self.path).query)
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(report_path.stat().st_size))
            if "download" in query:
                for key, value in attachment_headers(report_path).items():
                    self.send_header(key, value)
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
                two_factor = begin_two_factor_enrollment(username)
                self._send(
                    200,
                    render_login(two_factor=two_factor).encode("utf-8"),
                )
            except Exception as exc:
                self._send(400, render_setup(str(exc)).encode("utf-8"))
            return

        if path == "/login":
            raw = self._read_body().decode("utf-8")
            form = parse_qs(raw)
            challenge = (form.get("challenge") or [""])[0]
            code = (form.get("totp_code") or [""])[0]
            trust_device = bool((form.get("trust_device") or [""])[0])
            if challenge:
                payload = verify_two_factor_challenge(challenge)
                if not payload:
                    self._send(403, render_login("Two-factor challenge expired. Sign in again.").encode("utf-8"))
                    return
                username = str(payload.get("user", "")).strip()
                purpose = str(payload.get("purpose", "")).strip()
                managed = get_managed_user(username)
                if not managed or not managed.get("active", True):
                    self._send(403, render_login("Invalid login.").encode("utf-8"))
                    return
                if purpose == "enroll":
                    try:
                        managed = confirm_two_factor_enrollment(username, code)
                    except Exception as exc:
                        self._send(403, render_login(str(exc), two_factor=begin_two_factor_enrollment(username)).encode("utf-8"))
                        return
                    self._send(303, b"", "text/plain; charset=utf-8", login_headers(username, trust_device, managed))
                    return
                if purpose == "verify":
                    if not two_factor_enabled(managed) or not verify_totp_code(str(managed.get("totp_secret", "")), code):
                        self._send(403, render_login("Invalid authenticator code.", two_factor=two_factor_verify_context(username)).encode("utf-8"))
                        return
                    self._send(303, b"", "text/plain; charset=utf-8", login_headers(username, trust_device, managed))
                    return
                self._send(403, render_login("Invalid two-factor challenge.").encode("utf-8"))
                return

            username = (form.get("username") or [""])[0].strip()
            password = (form.get("password") or [""])[0]
            user = verify_login(username, password)
            if user:
                managed = get_managed_user(user) if has_managed_users() else None
                if managed:
                    if not two_factor_enabled(managed):
                        self._send(200, render_login(two_factor=begin_two_factor_enrollment(user)).encode("utf-8"))
                        return
                    trusted_cookie = self._cookie_value(TRUSTED_2FA_COOKIE)
                    if not verify_trusted_device(trusted_cookie, user, managed):
                        self._send(200, render_login(two_factor=two_factor_verify_context(user)).encode("utf-8"))
                        return
                    self._send(303, b"", "text/plain; charset=utf-8", login_headers(user))
                    return
                self._send(303, b"", "text/plain; charset=utf-8", login_headers(user))
                return
            self._send(403, render_login("Invalid login.", username_value=username).encode("utf-8"))
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

        if path == "/api/schedule":
            if not self._require_scan_permission():
                return
            try:
                payload = self._read_json()
                user = self._current_user() or "local"
                item = upsert_scan_schedule(payload, user)
                jobs = JOBS.list()
                reports = list_reports()
                schedule = list_scan_schedule(jobs, reports)
                self._json(200, {
                    "item": decorate_schedule_item(item, jobs, reports),
                    "schedule": schedule,
                    "overview": scan_overview(schedule, jobs, reports),
                })
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return

        if path.startswith("/api/schedule/") and path.endswith("/run"):
            if not self._require_scan_permission():
                return
            try:
                schedule_id = unquote(path.removeprefix("/api/schedule/").removesuffix("/run").strip("/"))
                item = get_scan_schedule(schedule_id)
                if not item:
                    self._json(404, {"error": "Schedule not found."})
                    return
                user = self._current_user() or "local"
                job = queue_schedule_job(item, user, "schedule")
                jobs = JOBS.list()
                reports = list_reports()
                schedule = list_scan_schedule(jobs, reports)
                self._json(201, {"job": job.snapshot(), "schedule": schedule, "overview": scan_overview(schedule, jobs, reports)})
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return

        if path.startswith("/api/users/") and path.endswith("/2fa-reset"):
            if not self._require_admin():
                return
            try:
                username = unquote(path.removeprefix("/api/users/").removesuffix("/2fa-reset").strip("/"))
                reset_user_two_factor(username, self._current_user() or "local")
                self._json(200, {"ok": True, "users": list_managed_users()})
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
        if path.startswith("/api/schedule/"):
            if not self._require_scan_permission():
                return
            try:
                schedule_id = unquote(path.rsplit("/", 1)[-1])
                if not delete_scan_schedule(schedule_id):
                    self._json(404, {"error": "Schedule not found."})
                    return
                jobs = JOBS.list()
                reports = list_reports()
                schedule = list_scan_schedule(jobs, reports)
                self._json(200, {"ok": True, "schedule": schedule, "overview": scan_overview(schedule, jobs, reports)})
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        self._send(404, b"Not found", "text/plain; charset=utf-8")


FRONTEND_DIR = BASE_DIR / "web"
TEMPLATE_DIR = FRONTEND_DIR / "templates"
STATIC_DIR = FRONTEND_DIR / "static"
APP_ROUTES = {
    "/dashboard": "dashboard.html",
    "/scans": "scans.html",
    "/reports": "reports.html",
    "/admin/users": "admin-users.html",
    "/admin/api-keys": "admin-api-keys.html",
    "/index.html": "dashboard.html",
}


def safe_static_path(url_path: str) -> Path:
    rel = unquote(url_path.removeprefix("/static/"))
    if not rel or rel.startswith("/"):
        raise FileNotFoundError("Invalid static path.")
    root = STATIC_DIR.resolve()
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise FileNotFoundError("Invalid static path.") from exc
    if not path.is_file():
        raise FileNotFoundError("Static asset not found.")
    return path


def render_template(name: str, replacements: dict[str, str] | None = None) -> str:
    path = (TEMPLATE_DIR / name).resolve()
    try:
        path.relative_to(TEMPLATE_DIR.resolve())
    except ValueError as exc:
        raise FileNotFoundError("Invalid template path.") from exc
    page = path.read_text(encoding="utf-8")
    for key, value in (replacements or {}).items():
        page = page.replace(key, value)
    return page


def render_setup(error: str = "") -> str:
    error_html = f"<p class='notice show'>{html.escape(error)}</p>" if error else ""
    return render_template("setup.html", {"__ERROR_HTML__": error_html})


def render_primary_login_form(username_value: str) -> str:
    password_label = "Password" if has_managed_users() or WEB_USERS else "Password / token"
    return f"""
    <form method="post" action="/login">
      <div class="field">
        <label for="username">User</label>
        <input id="username" name="username" type="text" value="{html.escape(username_value)}" autocomplete="username" autofocus>
      </div>
      <div class="field">
        <label for="password">{html.escape(password_label)}</label>
        <input id="password" name="password" type="password" autocomplete="current-password">
      </div>
      <button class="primary" type="submit"><i data-lucide="log-in"></i>Sign in</button>
    </form>
    """


def render_two_factor_form(context: dict[str, Any]) -> str:
    purpose = str(context.get("purpose", "verify"))
    username = html.escape(str(context.get("username", "")))
    challenge = html.escape(str(context.get("challenge", "")))
    trust_checked = "checked" if purpose == "enroll" else ""
    code_autofocus = "" if purpose == "enroll" else "autofocus"
    setup_html = ""
    if purpose == "enroll":
        qr = str(context.get("qr_data_uri", ""))
        uri = str(context.get("otpauth_uri", ""))
        secret = str(context.get("secret", ""))
        formatted_secret = str(context.get("formatted_secret", ""))
        qr_html = (
            f'<img src="{html.escape(qr)}" alt="Authenticator QR code">'
            if qr else '<div class="qr-fallback"><i data-lucide="qr-code"></i><span>Use setup key</span></div>'
        )
        setup_html = f"""
      <div class="twofa-setup">
        <div class="twofa-qr">{qr_html}</div>
        <div>
          <p class="twofa-copy">Scan the QR code or add the setup key manually in Google Authenticator, Microsoft Authenticator, 1Password or any TOTP app.</p>
          <div class="secret-box primary-secret">
            <span>Manual setup key</span>
            <code>{html.escape(formatted_secret)}</code>
          </div>
          <details class="setup-details">
            <summary>Show raw key and otpauth link</summary>
            <div class="secret-box">
              <span>Raw key</span>
              <code>{html.escape(secret)}</code>
            </div>
            <a class="otpauth-link" href="{html.escape(uri)}">Open in authenticator app</a>
          </details>
        </div>
      </div>
        """
    return f"""
    <form method="post" action="/login">
      <input type="hidden" name="username" value="{username}">
      <input type="hidden" name="challenge" value="{challenge}">
      {setup_html}
      <div class="field">
        <label for="totp_code">Authenticator code</label>
        <input id="totp_code" name="totp_code" type="text" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" autocomplete="one-time-code" placeholder="123456" {code_autofocus}>
      </div>
      <label class="inline-check trust-check">
        <span>Trust this device for 30 days</span>
        <input name="trust_device" value="1" type="checkbox" {trust_checked}>
      </label>
      <button class="primary" type="submit"><i data-lucide="shield-check"></i><span>Verify and continue</span></button>
    </form>
    """


def render_login(error: str = "", two_factor: dict[str, Any] | None = None, username_value: str | None = None) -> str:
    if two_factor:
        mode_text = (
            "Set up mandatory two-factor authentication"
            if two_factor.get("purpose") == "enroll"
            else "Enter your authenticator app code"
        )
        auth_form = render_two_factor_form(two_factor)
    else:
        mode_text = "Team login" if has_managed_users() or WEB_USERS else "Shared access token"
        auth_form = render_primary_login_form(username_value if username_value is not None else ("" if has_managed_users() or WEB_USERS else "team"))
    error_html = f"<p class='notice show'>{html.escape(error)}</p>" if error else ""
    return render_template(
        "login.html",
        {
            "__MODE_TEXT__": html.escape(mode_text),
            "__ERROR_HTML__": error_html,
            "__AUTH_FORM__": auth_form,
        },
    )


def render_app_page(url_path: str) -> str:
    return render_template(APP_ROUTES.get(url_path, "dashboard.html"))


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

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_DB.parent.mkdir(parents=True, exist_ok=True)
    SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
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
    scheduler_thread = None
    if SCHEDULE_POLL_SECONDS > 0:
        scheduler_thread = threading.Thread(target=schedule_loop, name="scan-scheduler", daemon=True)
        scheduler_thread.start()
        print(f"Scheduled scan runner enabled every {max(30, SCHEDULE_POLL_SECONDS)} seconds.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping web console.")
    finally:
        SCHEDULER_STOP.set()
        if scheduler_thread:
            scheduler_thread.join(timeout=2)
        EXECUTOR.shutdown(wait=False, cancel_futures=False)
        server.server_close()


if __name__ == "__main__":
    main()
