"""
EASM Scanner — Modul 6: Darknet / OSINT
=========================================
Suche nach geleakten E-Mails und Bewertung der Leak-Schwere.
"""

import config
from utils import get_logger, http_get, print_progress

log = get_logger("easm.darknet")


# ═════════════════════════════════════════════════════════════════════════════
#  E-Mail Leak Search
# ═════════════════════════════════════════════════════════════════════════════

def search_email_leaks(domain: str) -> dict:
    """
    Sucht nach geleakten E-Mail-Adressen der Zieldomain.
    Zwingt zur Nutzung der HIBP API, da tiefgehende OSINT-Analysen ohne API sinnlos sind.
    """
    print_progress("Darknet/OSINT", "Leak-Suche gestartet …")
    result = {
        "leaks_found": [],
        "breach_summary": [],
        "api_status": "OK",
    }

    hibp_key = config.API_KEYS.get("hibp", "")

    if hibp_key:
        _search_hibp(domain, hibp_key, result)
    else:
        result["api_status"] = "MISSING_API_KEY"
        log.warning("Kein HIBP API-Key konfiguriert. Darknet-Modul übersprungen.")

    return result


def _get_harvester_emails(domain: str) -> list[str]:
    """Sucht über theHarvester nach tatsächlichen Mitarbeiter-E-Mails (OSINT)."""
    import subprocess
    import tempfile
    import os
    import xml.etree.ElementTree as ET
    
    print_progress("Darknet/OSINT", "Sammle Mitarbeiter-Emails via OSINT (theHarvester) …")
    emails = []
    try:
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            out_file = tf.name
            
        # -b all ist zu langsam, wir nutzen schnelle Quellen
        cmd = ["theHarvester", "-d", domain, "-b", "bing,duckduckgo,crtsh", "-f", out_file]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        
        if os.path.exists(out_file):
            if os.path.getsize(out_file) > 0:
                tree = ET.parse(out_file)
                for email in tree.findall('.//email'):
                    if email.text and email.text.endswith(domain):
                        emails.append(email.text.lower().strip())
            os.remove(out_file)
    except FileNotFoundError:
        log.warning("  theHarvester nicht installiert. Überspringe Employee Recon.")
    except Exception as exc:
        log.debug(f"Harvester-Fehler: {exc}")
        
    return list(set(emails))


def _search_hibp(domain: str, api_key: str, result: dict):
    """Sucht über die HIBP API nach Domain-Breaches und spezifischen E-Mails."""
    try:
        resp = http_get(
            f"https://haveibeenpwned.com/api/v3/breaches",
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "EASM-Scanner-v1.0",
            },
            timeout=15,
        )

        if resp and resp.status_code == 200:
            all_breaches = resp.json()

            domain_lower = domain.lower()
            for breach in all_breaches:
                breach_domain = breach.get("Domain", "").lower()
                if breach_domain == domain_lower:
                    breach_info = _parse_breach(breach)
                    result["breach_summary"].append(breach_info)

            # Generiere Test-Ziele aus generischen + echten OSINT E-Mails
            emails_to_test = [
                f"info@{domain}", f"admin@{domain}", f"kontakt@{domain}", 
                f"support@{domain}", f"office@{domain}"
            ]
            
            # Echte Mitarbeiter-Mails über OSINT (theHarvester)
            scraped_emails = _get_harvester_emails(domain)
            if scraped_emails:
                log.info(f"  {len(scraped_emails)} echte Mitarbeiter-IDs gefunden.")
                emails_to_test.extend(scraped_emails)
                
            emails_to_test = list(set(emails_to_test))
            
            for email in emails_to_test:
                _check_email_hibp(email, api_key, result)

    except Exception as exc:
        log.warning(f"HIBP-API-Abfrage fehlgeschlagen: {exc}")


def _check_email_hibp(email: str, api_key: str, result: dict):
    """Prüft eine einzelne E-Mail-Adresse gegen HIBP."""
    try:
        import time
        time.sleep(1.5)  # Rate-Limiting: 1 Request pro 1.5 Sekunden (HIBP-Limit)

        resp = http_get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "EASM-Scanner-v1.0",
            },
            timeout=15,
        )

        if resp and resp.status_code == 200:
            breaches = resp.json()
            for breach in breaches:
                result["leaks_found"].append({
                    "email": email,
                    "breach_name": breach.get("Name", ""),
                    "breach_date": breach.get("BreachDate", ""),
                    "data_classes": breach.get("DataClasses", []),
                    "is_verified": breach.get("IsVerified", False),
                    "is_sensitive": breach.get("IsSensitive", False),
                })
            if breaches:
                log.warning(f"  {email}: in {len(breaches)} Breach(es) gefunden!")
        elif resp and resp.status_code == 404:
            pass  # Nicht gefunden — gut!
        elif resp and resp.status_code == 429:
            log.warning("  HIBP Rate-Limit erreicht, überspringe weitere Abfragen")

    except Exception:
        pass


def _parse_breach(breach: dict) -> dict:
    """Parst HIBP-Breach-Daten in ein einheitliches Format."""
    return {
        "name": breach.get("Name", ""),
        "title": breach.get("Title", ""),
        "domain": breach.get("Domain", ""),
        "breach_date": breach.get("BreachDate", ""),
        "added_date": breach.get("AddedDate", ""),
        "modified_date": breach.get("ModifiedDate", ""),
        "pwn_count": breach.get("PwnCount", 0),
        "data_classes": breach.get("DataClasses", []),
        "is_verified": breach.get("IsVerified", False),
        "is_sensitive": breach.get("IsSensitive", False),
        "is_retired": breach.get("IsRetired", False),
        "description": breach.get("Description", "")[:300],
    }


def _search_pastebin_dorks(domain: str, result: dict):
    """Sucht über DuckDuckGo nach Pastebin/Ghostbin Leaks ohne API Keys."""
    print_progress("Darknet/OSINT", "Zero-API Pastebin Dorking …")
    
    # Sucht nach Pastebin Dumps mit Passwörtern oder Configs der Domain
    query = f'site:pastebin.com "{domain}" (password OR secret OR token)'
    url = f"https://html.duckduckgo.com/html/?q={query}"
    
    try:
        # Tarnkappen-Modus für DDG
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        resp = http_get(url, headers=headers, timeout=10)
        
        if resp and resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            results = soup.find_all("a", class_="result__url", href=True)
            
            for link in results:
                href = link["href"]
                if "pastebin.com" in href:
                    result["leaks_found"].append({
                        "email": "DORK-MATCH",
                        "breach_name": "Open Pastebin Leak",
                        "data_classes": ["Passwords", "Config", "Source Code"],
                        "url": href,
                        "is_verified": False,
                        "is_sensitive": True,
                    })
                    log.critical(f"  🔴 PASTEBIN LEAK GEFUNDEN: {href}")
                    
    except Exception as exc:
        log.debug(f"DuckDuckGo Dorking Fehler: {exc}")


def _search_leakix(domain: str, result: dict):
    """Durchsucht LeakIX (Free API Endpoint) nach offenen Datenbanken der Domain."""
    print_progress("Darknet/OSINT", "Suche auf LeakIX (Keyless API) …")
    
    # LeakIX erlaubt limitierte Keyless Querys über deren Web/Search
    url = f"https://leakix.net/search?q=%2Bhost%3A%22{domain}%22"
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Accept": "application/json"}
        resp = http_get(url, headers=headers, timeout=10)
        
        if resp and resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            
            # Simple DOM parsing for LeakIX search results 
            # (they inject data directly into HTML panels)
            found_panels = soup.find_all("div", class_="col-lg-12")
            if len(found_panels) > 2: # Ignore menu panels
                result["breach_summary"].append({
                    "name": "LeakIX Database Exposure",
                    "domain": domain,
                    "description": "LeakIX indicates open ports or leaked databases for this domain. Visit leakix.net for details.",
                    "is_verified": True,
                    "is_sensitive": True
                })
                log.critical(f"  🔴 LEAKIX DATABASE EXPOSURE ENTDECKT.")
    except Exception as exc:
        log.debug(f"LeakIX Error: {exc}")


def _search_github_keyless(domain: str, result: dict):
    """Sucht auf GitHub via Public Search (ohne API Token) nach Env-Leaks."""
    print_progress("Darknet/OSINT", "Zero-API GitHub Scraping …")
    
    # Dorks
    url = f"https://github.com/search?q=%22{domain}%22+password+OR+secret+OR+api_key&type=code"
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"}
        resp = http_get(url, headers=headers, timeout=10)
        
        if resp and resp.status_code == 200:
            if "We couldn’t find any code matching" not in resp.text:
                result["breach_summary"].append({
                    "name": "Public GitHub Code Leaks",
                    "domain": domain,
                    "description": "Found instances of the domain combined with 'password' or 'secret' on GitHub Code search.",
                    "is_verified": False,
                    "is_sensitive": True
                })
                log.critical("  🔴 GITHUB PUBLIC LEAK (Möglicherweise Secrets geleakt)")
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════════
#  Hauptfunktion Modul 6
# ═════════════════════════════════════════════════════════════════════════════

def run(domain: str) -> dict:
    """Führt alle Darknet-/OSINT-Checks aus."""
    result = search_email_leaks(domain)
    # 0-Day / No-API Leak Search hinzufügen
    _search_pastebin_dorks(domain, result)
    _search_leakix(domain, result)
    _search_github_keyless(domain, result)
    return result
