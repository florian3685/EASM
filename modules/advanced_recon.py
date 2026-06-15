"""
EASM Scanner — Modul 7: Advanced Recon
========================================
Extreme Deep-Dive Scans: JavaScript Secrets, Wayback History, Subdomain Takeovers & Database Hunting.
"""

import re
import socket
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from utils import get_logger, http_get, print_progress, resolve_hostname

log = get_logger("easm.advanced_recon")

# ── RegEx Signaturen für JavaScript Secrets ──
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Standard API": r"[s|p]k_live_[0-9a-zA-Z]{24}",
    "Firebase DB": r"[a-z0-9\-]+\.firebaseio\.com",
    "Slack Token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
    "JSON Web Token (JWT)": r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
}

# ── Subdomain Takeover Signaturen (CNAME Pattern -> HTML Signatur) ──
TAKEOVER_SIGNATURES = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "404 Web Site not found",
    "myshopify.com": "Sorry, this shop is currently unavailable",
}


def check_js_secrets(domain: str) -> list[dict]:
    """Sucht in JavaScript-Dateien nach kritischen Secrets und API Keys."""
    print_progress("Advanced Recon", "JavaScript Secret Extraction …")
    found_secrets = []
    
    try:
        # 1. HTML der Startseite holen
        base_url = f"https://{domain}"
        resp = http_get(base_url, timeout=10)
        if not resp or not resp.text:
            return found_secrets
            
        soup = BeautifulSoup(resp.text, "html.parser")
        js_files = []
        
        # 2. JS Links extrahieren
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                full_url = urljoin(base_url, src)
                js_files.append(full_url)
                
        js_files = list(set(js_files))[:20]  # Max 20 Files um Zeit zu sparen
        
        if js_files:
            log.info(f"  Untersuche {len(js_files)} verlinkte JavaScript-Dateien auf Secrets...")
            
        for js_url in js_files:
            js_resp = http_get(js_url, timeout=5)
            if js_resp and js_resp.text:
                text = js_resp.text
                
                # Suchen nach jedem Secret-Pattern
                for secret_name, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, text)
                    if matches:
                        # Bereinigen und Deduplizieren
                        unique_matches = list(set(matches))
                        for m in unique_matches:
                            # Ignoriere "Fake" JWTs
                            if secret_name == "JSON Web Token (JWT)" and len(m) < 40:
                                continue
                                
                            found_secrets.append({
                                "type": secret_name,
                                "match": f"{m[:8]}...{m[-4:]}" if len(m) > 15 else m, # Maskierung aus Sicherheitsgründen
                                "source": js_url
                            })
                            log.warning(f"  Secret gefunden: {secret_name} in {js_url}")
                            
    except Exception as exc:
        log.debug(f"Fehler bei JS Secret Extraction: {exc}")
        
    return found_secrets


def check_wayback_history(domain: str) -> list[str]:
    """Ruft Archive.org/cdx ab um nicht mehr gelistete URLs (APIs) zu finden."""
    print_progress("Advanced Recon", "Wayback Machine Historical Endpoints …")
    historical_urls = []
    
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
    try:
        resp = http_get(url, timeout=30)
        if resp and resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 1:
                # Erste Zeile ["original"] skippen (Header)
                for row in data[1:]:
                    if row and len(row) > 0:
                        historical_url = row[0]
                        # Wir interessieren uns besonders für APIs, Admin, Config
                        if any(x in historical_url.lower() for x in ["api", "admin", "config", ".json", ".sql", ".bak"]):
                            historical_urls.append(historical_url)
                            
        # Deduplizieren
        historical_urls = list(set(historical_urls))
        if historical_urls:
            log.info(f"  {len(historical_urls)} potenziell kritische Endpoint-Historien gefunden.")
            
    except Exception as exc:
        log.debug(f"Wayback Machine Fehler: {exc}")
        
    return historical_urls


def check_data_stores(domain: str) -> list[dict]:
    """Brute-Force Ping auf kritische Datenbank-Ports nach ungesicherten Datastores."""
    print_progress("Advanced Recon", "Data-Store Hunting (MongoDB, Redis, Elastic) …")
    exposures = []
    
    ips = resolve_hostname(domain)
    if not ips:
        return exposures
        
    target_ip = ips[0]
    ports = {
        27017: "MongoDB",
        6379: "Redis",
        9200: "ElasticSearch"
    }
    
    log.info(f"  Scanne {target_ip} auf exponierte NoSQL-Datenbanken...")
    
    for port, name in ports.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                if sock.connect_ex((target_ip, port)) == 0:
                    
                    details = "Open Port"
                    # Versuche Basis-Kommunikation für Elastic
                    if port == 9200:
                        resp = http_get(f"http://{target_ip}:9200", timeout=2)
                        if resp and "cluster_name" in resp.text:
                            details = "Unauthenticated ElasticSearch Cluster discovered!"
                    
                    exposures.append({
                        "database": name,
                        "ip": target_ip,
                        "port": port,
                        "status": "EXPOSED (CRITICAL)",
                        "details": details
                    })
                    log.warning(f"  KRITISCH: Exponierte {name} auf {target_ip}:{port} entdeckt!")
        except Exception:
            pass
            
    return exposures


def check_subdomain_takeovers(domain: str) -> list[dict]:
    """Testet CNAMES von Subdomains auf Vulnerabilitäten zur direkten Account-Übernahme."""
    print_progress("Advanced Recon", "Subdomain Takeover Hunting (CNAME checks) …")
    takeovers = []
    
    # Subdomain enumeration via the multi-source engine (passive only, fast)
    from modules.subdomain_enum import enumerate_all
    enum = enumerate_all(domain, bruteforce=False, permute=False, validate=False)
    subdomains = list(set(enum["subdomains"] + [domain, f"www.{domain}"]))
    
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    import concurrent.futures

    def check_sub(sub: str):
        try:
            answers = resolver.resolve(sub, "CNAME")
            for rdata in answers:
                cname = str(rdata.target).rstrip(".").lower()
                
                # Check for vulnerable cloud providers
                for provider, sig in TAKEOVER_SIGNATURES.items():
                    if provider in cname:
                        # Fetch and verify signature
                        resp = http_get(f"http://{sub}", timeout=3, allow_redirects=True)
                        if resp and sig in resp.text:
                            return {
                                "subdomain": sub,
                                "cname_target": cname,
                                "provider": provider,
                                "status": "VULNERABLE (CRITICAL)",
                                "assessment": f"Subdomain can be hijacked by registering account at {provider}!"
                            }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            pass
        return None

    log.info(f"  Analysiere CNAMES von {len(subdomains)} Subdomains auf Übernahme-Signaturen...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for res in executor.map(check_sub, subdomains):
            if res:
                takeovers.append(res)
                log.critical(f"  🔴 SUBDOMAIN TAKEOVER GEFUNDEN: {res['subdomain']} verweist auf ein unregistriertes {res['provider']}!")

    return takeovers


# ═════════════════════════════════════════════════════════════════════════════
#  Hauptfunktion Modul 7
# ═════════════════════════════════════════════════════════════════════════════

def run(domain: str) -> dict:
    """Führt alle Advanced Recon Checks aus."""
    result = {
        "javascript_secrets": check_js_secrets(domain),
        "historical_endpoints": check_wayback_history(domain),
        "datastore_exposures": check_data_stores(domain),
        "subdomain_takeovers": check_subdomain_takeovers(domain),
    }
    return result
