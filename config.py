"""
EASM Scanner — Zentrale Konfiguration
======================================
Alle einstellbaren Parameter, API-Keys und Referenzdaten.
API-Keys werden bevorzugt aus Umgebungsvariablen gelesen.
"""

import os
try:
    from dotenv import load_dotenv
    base_dir = os.path.dirname(__file__)
    data_dir = os.environ.get("EASM_DATA_DIR", "")
    dotenv_path = (
        os.environ.get("EASM_ENV_FILE")
        or (os.path.join(data_dir, ".env") if data_dir else os.path.join(base_dir, ".env"))
    )
    load_dotenv(dotenv_path)
except ImportError:
    pass

# ── API Keys & Webhooks (via .env oder Umgebungsvariablen) ──────────────────────────────
API_KEYS = {
    "virustotal": os.environ.get("VT_API_KEY", ""),
    "hibp": os.environ.get("HIBP_API_KEY", ""),          # Have I Been Pwned
    "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY", ""),
    "google_safebrowsing": os.environ.get("GSB_API_KEY", ""),
    "shodan": os.environ.get("SHODAN_API_KEY", ""),
    "github": os.environ.get("GITHUB_TOKEN", ""),
}
WEBHOOK_URL = os.environ.get("EASM_WEBHOOK_URL", "")     # Slack/Discord URLs

# ── Netzwerk & Anti-Bot ──────────────────────────────────────────────────────
STEALTH_MODE = False   # Wird über CLI eingeschaltet
STEALTH_JITTER = (0.5, 2.5)  # Zufällige Latenz zwischen Requests in Sekunden

TIMEOUT = 8            # Sekunden für TCP-Verbindungen
HTTP_TIMEOUT = 10      # Sekunden für HTTP-Requests
DNS_TIMEOUT = 5        # Sekunden für DNS-Abfragen
MAX_RETRIES = 2        # Wiederholungsversuche bei Fehlern

# Fast Web Asset Intelligence limits. Keep this module bounded so "all modules"
# scans gain coverage without turning into a full crawler.
WEB_INTEL_MAX_HOSTS = int(os.environ.get("WEB_INTEL_MAX_HOSTS", "35"))
WEB_INTEL_MAX_PATH_ASSETS = int(os.environ.get("WEB_INTEL_MAX_PATH_ASSETS", "12"))
WEB_INTEL_MAX_WORKERS = int(os.environ.get("WEB_INTEL_MAX_WORKERS", "12"))
WEB_INTEL_TIMEOUT = int(os.environ.get("WEB_INTEL_TIMEOUT", "5"))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

# Standard-Browser-Header für HTTP-Evasion
EVASION_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

# ── Port-Scanning ─────────────────────────────────────────────────────────────
SCAN_PORTS = {
    "web":        [80, 443, 8080, 8443, 8000, 8888],
    "mail":       [25, 110, 143, 465, 587, 993, 995],
    "ssh":        [22],
    "ftp":        [21],
    "smb":        [445, 139],
    "database":   [3306, 5432, 1433, 27017, 6379],
    "monitoring": [161, 162],   # SNMP
    "rdp":        [3389],
    "vpn":        [1194, 500, 4500, 1701],
    "dns":        [53],
}

ALL_PORTS = sorted(set(p for ports in SCAN_PORTS.values() for p in ports))

# ── Login-Pfade ───────────────────────────────────────────────────────────────
LOGIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/login", "/signin", "/auth", "/user/login",
    "/cpanel", "/webmail", "/phpmyadmin", "/adminer",
    "/remote/login",          # FortiGate VPN
    "/sslvpn",                # Generic SSL VPN
    "/vpn",                   # Generic VPN
    "/webvpn",                # Cisco WebVPN
    "/dana-na/auth/url_default/welcome.cgi",  # Pulse Secure
    "/global-protect/login.esp",              # Palo Alto
    "/__sophos",              # Sophos VPN
]

# ── Bekannte Tracker ──────────────────────────────────────────────────────────
TRACKER_SIGNATURES = {
    "Google Analytics":     ["google-analytics.com", "googletagmanager.com", "gtag/js"],
    "Meta Pixel":           ["connect.facebook.net", "fbevents.js", "facebook.com/tr"],
    "Hotjar":               ["hotjar.com", "static.hotjar.com"],
    "LinkedIn Insight":     ["snap.licdn.com", "linkedin.com/px"],
    "TikTok Pixel":         ["analytics.tiktok.com"],
    "Twitter Pixel":        ["static.ads-twitter.com", "t.co/i/adsct"],
    "Pinterest Tag":        ["pintrk", "ct.pinterest.com"],
    "Microsoft Clarity":    ["clarity.ms"],
    "Matomo/Piwik":         ["matomo", "piwik"],
}

COOKIE_BANNER_SIGNATURES = [
    "cookiebot", "onetrust", "cookieconsent", "cookie-consent",
    "cookie-notice", "cookie-law", "gdpr", "trustarc",
    "quantcast", "usercentrics", "klaro", "consentmanager",
]

# ── Sicherheitsheader ─────────────────────────────────────────────────────────
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

# ── DKIM-Selektoren ───────────────────────────────────────────────────────────
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "dkim", "mail", "k1", "s1", "s2", "email",
    "mandrill", "mxvault", "protonmail",
]

# ── Mail-Blacklists (DNSBL) ──────────────────────────────────────────────────
MAIL_DNSBLS = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "bl.spamcop.net",
    "dnsbl-1.uceprotect.net",
    "psbl.surriel.com",
    "db.wpbl.info",
]

# ── CDN / WAF Signaturen ─────────────────────────────────────────────────────
CDN_WAF_HEADERS = {
    "Cloudflare":  ["cf-ray", "cf-cache-status", "cf-request-id"],
    "Akamai":      ["x-akamai-transformed", "akamai-origin-hop"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "Fastly":      ["x-served-by", "x-cache", "x-fastly-request-id"],
    "Incapsula":   ["x-iinfo", "x-cdn"],
    "Azure CDN":   ["x-msedge-ref"],
    "Sucuri":      ["x-sucuri-id", "x-sucuri-cache"],
}

# ── Severity Levels ───────────────────────────────────────────────────────────
SEVERITY = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}
