"""
EASM Scanner — Shared Utilities
================================
Logging, HTTP-Wrapper, IP/ASN-Helfer.
"""

import logging
import random
import socket
import time
from typing import Optional

import requests
from colorama import Fore, Style, init as colorama_init

import config

colorama_init(autoreset=True)

# ── Logging ───────────────────────────────────────────────────────────────────

class ColorFormatter(logging.Formatter):
    """Farbiges Logging auf der Konsole."""
    COLORS = {
        logging.DEBUG:    Fore.CYAN,
        logging.INFO:     Fore.GREEN,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, "")
        record.msg = f"{color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)


def get_logger(name: str) -> logging.Logger:
    """Erzeugt einen Logger mit farbiger Konsolenausgabe."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(ColorFormatter("[%(asctime)s] %(levelname)-8s %(name)-28s │ %(message)s", datefmt="%H:%M:%S"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


log = get_logger("easm.utils")

# ── HTTP-Wrapper ──────────────────────────────────────────────────────────────

import httpx
import ssl

# HTTP/2 needs the optional 'h2' dependency. Fall back gracefully if missing.
try:
    import h2  # noqa: F401
    _HTTP2 = True
except ImportError:
    _HTTP2 = False
    logging.getLogger("easm.utils").info(
        "h2 not installed — falling back to HTTP/1.1. `pip install h2` for HTTP/2 support."
    )

def get_advanced_ssl_context() -> ssl.SSLContext:
    """
    Krasses TLS-Fingerprinting Profil:
    Diese Cipher-Suite imitiert 1:1 moderne Browser (wie Chrome 120+).
    Standard-Python-Requests haben einen extrem primitiven JA3-Fingerprint,
    der von Cloudflare, Akamai und Mailservern sofort geblockt wird.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    context.set_ciphers(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
    )
    return context


def _get_evasion_headers() -> dict:
    """Generiert rotierende Browser-Header zur Umgehung von Bot-Protection."""
    headers = config.EVASION_HEADERS.copy()
    headers["User-Agent"] = random.choice(config.USER_AGENTS)
    ua = headers["User-Agent"]
    if "Chrome/" in ua:
        try:
            v = ua.split("Chrome/")[1].split(".")[0]
            headers["Sec-Ch-Ua"] = f'"Not_A Brand";v="8", "Chromium";v="{v}", "Google Chrome";v="{v}"'
            headers["Sec-Ch-Ua-Mobile"] = "?0"
            headers["Sec-Ch-Ua-Platform"] = '"Windows"' if "Windows" in ua else '"macOS"' if "Mac OS" in ua else '"Linux"'
        except IndexError:
            pass
    return headers


def _build_verify(verify_ssl: bool):
    """Build the verify argument for httpx.

    verify=True       → strict cert validation (default, safe).
    verify=False      → disabled validation (legacy/self-signed targets).
    """
    if verify_ssl:
        return True
    ctx = get_advanced_ssl_context()  # already CERT_NONE + browser cipher set
    return ctx


def http_get(url: str, timeout: int = None, headers: dict = None,
             allow_redirects: bool = True, verify_ssl: bool = True) -> Optional[httpx.Response]:
    """HTTP GET with retry, jitter, browser-like headers/TLS."""
    if config.STEALTH_MODE:
        time.sleep(random.uniform(*config.STEALTH_JITTER))

    timeout_val = timeout or config.HTTP_TIMEOUT
    _headers = _get_evasion_headers()
    if headers:
        _headers.update(headers)

    verify_arg = _build_verify(verify_ssl)
    for attempt in range(1, config.MAX_RETRIES + 1):
        try:
            with httpx.Client(http2=_HTTP2, verify=verify_arg,
                              follow_redirects=allow_redirects) as client:
                return client.get(url, timeout=timeout_val, headers=_headers)
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as exc:
            if attempt < config.MAX_RETRIES:
                time.sleep(2 * attempt)
            else:
                log.debug(f"HTTP GET failed for {url}: {exc}")
                return None
        except httpx.RequestError as exc:
            log.debug(f"HTTP GET RequestError for {url}: {exc}")
            return None
    return None


def http_head(url: str, timeout: int = None, verify_ssl: bool = True) -> Optional[httpx.Response]:
    """HTTP HEAD for fast header checks."""
    if config.STEALTH_MODE:
        time.sleep(random.uniform(*config.STEALTH_JITTER))

    timeout_val = timeout or config.HTTP_TIMEOUT
    _headers = _get_evasion_headers()
    verify_arg = _build_verify(verify_ssl)

    for attempt in range(1, config.MAX_RETRIES + 1):
        try:
            with httpx.Client(http2=_HTTP2, verify=verify_arg, follow_redirects=True) as client:
                return client.head(url, timeout=timeout_val, headers=_headers)
        except httpx.RequestError:
            if attempt < config.MAX_RETRIES:
                time.sleep(1)

    return None


# ── IP / DNS Helfer ───────────────────────────────────────────────────────────

def resolve_hostname(hostname: str) -> list[str]:
    """Löst einen Hostnamen in alle zugehörigen IPs auf."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list(set(addr[4][0] for addr in results))
    except socket.gaierror:
        return []


def reverse_dns(ip: str) -> Optional[str]:
    """Reverse-DNS-Lookup für eine IP-Adresse."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def ip_to_reverse(ip: str) -> str:
    """Konvertiert eine IPv4-Adresse in das Reverse-DNS-Format (für DNSBL)."""
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(reversed(parts))
    return ip


def get_asn_info(ip: str) -> dict:
    """ASN-Informationen über ipwhois für eine IP-Adresse."""
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=0)
        return {
            "asn": result.get("asn", ""),
            "asn_description": result.get("asn_description", ""),
            "asn_country_code": result.get("asn_country_code", ""),
            "network_cidr": result.get("network", {}).get("cidr", "") if result.get("network") else "",
        }
    except Exception as exc:
        log.debug(f"ASN-Lookup fehlgeschlagen für {ip}: {exc}")
        return {"asn": "", "asn_description": "", "asn_country_code": "", "network_cidr": ""}


def check_dnsbl(ip: str, dnsbl: str) -> bool:
    """Prüft, ob eine IP in einer DNS-Blacklist steht."""
    import dns.resolver
    query = f"{ip_to_reverse(ip)}.{dnsbl}"
    try:
        dns.resolver.resolve(query, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.Timeout, Exception):
        return False


# ── Fortschrittsanzeige ───────────────────────────────────────────────────────

def print_banner():
    """Druckt das Scanner-Banner."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ███████╗ █████╗ ███████╗███╗   ███╗                       ║
║   ██╔════╝██╔══██╗██╔════╝████╗ ████║                       ║
║   █████╗  ███████║███████╗██╔████╔██║                       ║
║   ██╔══╝  ██╔══██║╚════██║██║╚██╔╝██║                       ║
║   ███████╗██║  ██║███████║██║ ╚═╝ ██║                       ║
║   ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝                       ║
║                                                              ║
║   External Attack Surface Management Scanner                 ║
║   v1.0.0                                                     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


def print_section(title: str):
    """Druckt eine Abschnittsüberschrift."""
    width = 60
    print(f"\n{Fore.CYAN}{'═' * width}")
    print(f"  {Style.BRIGHT}{title}")
    print(f"{'═' * width}{Style.RESET_ALL}\n")


def print_progress(module_name: str, step: str):
    """Druckt einen Fortschrittsindikator."""
    print(f"  {Fore.YELLOW}▸{Style.RESET_ALL} [{module_name}] {step}")


# ── Webhook Alerts (Phase 5) ──────────────────────────────────────────────────

def send_webhook_alert(message: str, is_critical: bool = False):
    """Sendet asynchron eine Alert-Nachricht an den konfigurierten Webhook (Slack/Discord)."""
    if not config.WEBHOOK_URL:
        return
        
    color = 16711680 if is_critical else 3447003  # Rot oder Blau (für Discord Embeds nützlich)
    
    payload = {
        "content": f"🚨 **Kritischer EASM Alert** 🚨\n{message}" if is_critical else f"ℹ️ **EASM Alert**\n{message}",
        "embeds": [{
            "title": "EASM Scanner State Diff",
            "description": message,
            "color": color
        }]
    }
    
    # Da Webhooks oft blockieren, kapseln wir es im eigenen Background-Thread
    import threading
    def _send():
        try:
            with httpx.Client(verify=False) as client:
                client.post(config.WEBHOOK_URL, json=payload, timeout=5)
        except Exception as exc:
            log.debug(f"Webhook Senden fehlgeschlagen: {exc}")
            
    threading.Thread(target=_send, daemon=True).start()

