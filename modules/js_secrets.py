"""
EASM Scanner — Module 13: JavaScript Secrets Scanner
======================================================
Crawls the homepage + linked JS files and greps for leaked
credentials, API tokens, AWS keys, JWT secrets, etc.

Sources of truth for regexes:
  - GitHub secret-scanning patterns
  - TruffleHog detector rules
  - Sourcegraph leaked-secret patterns
"""

from __future__ import annotations

import concurrent.futures as cf
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from utils import get_logger, http_get, print_progress

log = get_logger("easm.js_secrets")


# Each entry: (label, regex, severity, optional entropy floor for a capture group)
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("AWS Access Key",         re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"), "CRITICAL"),
    ("AWS Secret Key",         re.compile(r"(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]"), "CRITICAL"),
    ("Google API Key",         re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "HIGH"),
    ("Google OAuth Token",     re.compile(r"\bya29\.[0-9A-Za-z\-_]+\b"), "HIGH"),
    ("Firebase URL",           re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), "MEDIUM"),
    ("Stripe Live Key",        re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "CRITICAL"),
    ("Stripe Publishable",     re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"), "LOW"),
    ("Slack Token",            re.compile(r"\bxox[baprs]-[0-9a-zA-Z\-]{10,72}\b"), "CRITICAL"),
    ("Slack Webhook",          re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}"), "HIGH"),
    ("GitHub Token",           re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "CRITICAL"),
    ("GitLab Token",           re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "CRITICAL"),
    ("Mailgun API Key",        re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "HIGH"),
    ("SendGrid API Key",       re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "CRITICAL"),
    ("Twilio API Key",         re.compile(r"\bSK[a-z0-9]{32}\b"), "HIGH"),
    ("Twilio Account SID",     re.compile(r"\bAC[a-z0-9]{32}\b"), "MEDIUM"),
    ("Heroku API Key",         re.compile(r"(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"), "HIGH"),
    ("Square Access Token",    re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b"), "CRITICAL"),
    ("Square OAuth Secret",    re.compile(r"\bsq0csp-[0-9A-Za-z\-_]{43}\b"), "CRITICAL"),
    ("PayPal Braintree Token", re.compile(r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"), "CRITICAL"),
    ("Mapbox Token",           re.compile(r"\bpk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"), "MEDIUM"),
    ("JWT",                    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "MEDIUM"),
    ("Private Key (PEM)",      re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "CRITICAL"),
    ("Basic Auth in URL",      re.compile(r"https?://[^\s/'\"]+:[^\s/'\"@]+@[^\s'\"]+"), "HIGH"),
    ("Generic API Key",        re.compile(r"(?i)(api[_-]?key|apikey|x-api-key)['\"\s:=]+['\"]?([A-Za-z0-9_\-]{24,})"), "MEDIUM"),
    ("Generic Bearer Token",   re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.=]{30,})"), "MEDIUM"),
    ("Hardcoded Password",     re.compile(r"(?i)(password|passwd|pwd)['\"\s:=]+['\"]([^'\"\s]{8,})['\"]"), "MEDIUM"),
]

# False-positive filters: don't flag obvious test/example values.
_FP_KEYWORDS = ("example", "your-", "yourkey", "xxxxxx", "placeholder",
                "sample", "demo", "test_", "fake", "<your", "ENTER_YOUR",
                "REDACTED", "REPLACE", "{{", "}}", "process.env")


def _is_false_positive(match_text: str) -> bool:
    low = match_text.lower()
    return any(fp in low for fp in _FP_KEYWORDS)


def _scan_text(text: str, source_url: str) -> list[dict]:
    findings: list[dict] = []
    for label, pattern, severity in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            matched = m.group(0)
            if len(matched) > 200:
                matched = matched[:200] + "…"
            if _is_false_positive(matched):
                continue
            findings.append({
                "type": label,
                "severity": severity,
                "url": source_url,
                "match": matched,
            })
    return findings


def _extract_js_urls(html_text: str, base_url: str) -> set[str]:
    soup = BeautifulSoup(html_text, "html.parser")
    base_host = urlparse(base_url).netloc
    js_urls: set[str] = set()
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            full = urljoin(base_url, src)
            # Only same-origin or well-known CDNs of the target's apps
            if urlparse(full).netloc.endswith(base_host) or _likely_first_party(full, base_host):
                js_urls.add(full)
    return js_urls


def _likely_first_party(url: str, base_host: str) -> bool:
    parsed = urlparse(url)
    netloc = parsed.netloc
    # Same registrable suffix heuristic — match last 2 labels.
    parts_a = netloc.split(".")
    parts_b = base_host.split(".")
    if len(parts_a) >= 2 and len(parts_b) >= 2:
        return parts_a[-2:] == parts_b[-2:]
    return False


def _scan_url(url: str) -> list[dict]:
    resp = http_get(url, timeout=15, verify_ssl=False)
    if not resp or resp.status_code >= 400:
        return []
    return _scan_text(resp.text or "", url)


def run(domain: str) -> dict:
    print_progress("JS Secrets", f"Crawling {domain} for inline + linked JS …")
    homepage = None
    for scheme in ("https", "http"):
        homepage = http_get(f"{scheme}://{domain}", timeout=15, verify_ssl=False)
        if homepage and homepage.status_code < 400:
            base_url = f"{scheme}://{domain}"
            break
    else:
        log.warning(f"Homepage not reachable for {domain}")
        return {"findings": [], "scanned_urls": []}

    inline_findings = _scan_text(homepage.text or "", base_url)
    js_urls = _extract_js_urls(homepage.text or "", base_url)
    log.info(f"Found {len(js_urls)} same-origin JS files to scan")

    findings: list[dict] = list(inline_findings)
    if js_urls:
        with cf.ThreadPoolExecutor(max_workers=10) as ex:
            for f in ex.map(_scan_url, js_urls):
                findings.extend(f)

    # Deduplicate
    seen = set()
    unique: list[dict] = []
    for f in findings:
        key = (f["type"], f["match"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    log.info(f"JS Secrets Scan: {len(unique)} unique findings across {len(js_urls)+1} resources")
    return {
        "findings": unique,
        "scanned_urls": [base_url] + sorted(js_urls),
    }
