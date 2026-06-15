"""
EASM Scanner — Modul 5: Datenschutz & Reputation
==================================================
Web-Zertifikate (TLS-Deep-Scan), Tracker, Sicherheitsheader, Reputation.
"""

import re
import ssl
import socket
from datetime import datetime, timezone

import config
from utils import get_logger, http_get, print_progress

log = get_logger("easm.privacy_reputation")


# ═════════════════════════════════════════════════════════════════════════════
#  Web-Verschlüsselung (SSL/TLS)
# ═════════════════════════════════════════════════════════════════════════════

def check_web_tls(domain: str) -> dict:
    """
    Analysiert die TLS-Konfiguration des Webservers.
    Prüft Zertifikatsgültigkeit, Key-Stärke, Protokollversionen.
    """
    print_progress("Privacy", "TLS-Zertifikat prüfen …")
    result = {
        "certificate": {},
        "protocol": "",
        "cipher_suite": "",
        "deprecated_protocols": [],
        "issues": [],
    }

    # Hauptverbindung aufbauen
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=config.TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                result["protocol"] = tls_sock.version()
                cipher = tls_sock.cipher()
                result["cipher_suite"] = cipher[0] if cipher else ""

                # Zertifikat analysieren
                cert_bin = tls_sock.getpeercert(binary_form=True)
                cert_dict = tls_sock.getpeercert()

                if cert_dict:
                    not_after = datetime.strptime(cert_dict["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    not_before = datetime.strptime(cert_dict["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

                    result["certificate"] = {
                        "subject": dict(x[0] for x in cert_dict.get("subject", ())),
                        "issuer": dict(x[0] for x in cert_dict.get("issuer", ())),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "serial_number": cert_dict.get("serialNumber", ""),
                        "san": [entry[1] for entry in cert_dict.get("subjectAltName", ())],
                        "is_expired": not_after < datetime.now(timezone.utc),
                        "days_until_expiry": (not_after - datetime.now(timezone.utc)).days,
                        "is_self_signed": cert_dict.get("subject") == cert_dict.get("issuer"),
                    }

                    if result["certificate"]["is_expired"]:
                        result["issues"].append("Zertifikat ist abgelaufen!")
                        log.warning("  Zertifikat ist ABGELAUFEN ✗")
                    elif result["certificate"]["days_until_expiry"] < 30:
                        result["issues"].append(f"Zertifikat läuft in {result['certificate']['days_until_expiry']} Tagen ab")
                        log.warning(f"  Zertifikat läuft in {result['certificate']['days_until_expiry']} Tagen ab ⚠")
                    else:
                        log.info(f"  Zertifikat gültig, läuft in {result['certificate']['days_until_expiry']} Tagen ab ✓")

                    if result["certificate"]["is_self_signed"]:
                        result["issues"].append("Self-Signed-Zertifikat!")

                # Key-Stärke (aus binärem Zertifikat)
                if cert_bin:
                    try:
                        from cryptography import x509 as cx509
                        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
                        cert_obj = cx509.load_der_x509_certificate(cert_bin)
                        pub_key = cert_obj.public_key()
                        key_size = getattr(pub_key, "key_size", None)
                        
                        alg_name = "Unbekannt"
                        if isinstance(pub_key, rsa.RSAPublicKey):
                            alg_name = "RSA"
                            if key_size and key_size < 2048:
                                result["issues"].append(f"Schwacher {alg_name}-Schlüssel: {key_size} Bit (min. 2048 empfohlen)")
                        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                            alg_name = "ECC"
                            if key_size and key_size < 256:
                                result["issues"].append(f"Schwacher {alg_name}-Schlüssel: {key_size} Bit (min. 256 empfohlen)")
                        else:
                            alg_name = pub_key.__class__.__name__
                        
                        result["certificate"]["key_size"] = key_size
                        result["certificate"]["key_alg"] = alg_name
                    except Exception as e:
                        pass

    except ssl.CertificateError as exc:
        result["issues"].append(f"Zertifikatsfehler: {exc}")
        log.warning(f"  Zertifikatsfehler: {exc}")
    except Exception as exc:
        result["issues"].append(f"TLS-Verbindung fehlgeschlagen: {exc}")
        log.warning(f"  TLS-Verbindung fehlgeschlagen: {exc}")

    # Deprecated Protocols prüfen (SSLv3, TLS 1.0, TLS 1.1)
    result["deprecated_protocols"] = _check_deprecated_protocols(domain)

    return result


def _check_deprecated_protocols(domain: str) -> list[dict]:
    """Prüft ob deprecated TLS-Versionen noch unterstützt werden."""
    deprecated = []
    protocols_to_check = {
        "TLSv1": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
    }

    for proto_name, proto_version in protocols_to_check.items():
        if proto_version is None:
            continue
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = proto_version
            context.maximum_version = proto_version

            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    deprecated.append({
                        "protocol": proto_name,
                        "supported": True,
                        "risk": "HIGH — veraltetes Protokoll, sollte deaktiviert werden",
                    })
                    log.warning(f"  Veraltetes Protokoll {proto_name} wird unterstützt ✗")
        except Exception:
            # Verbindung fehlgeschlagen → Protokoll nicht unterstützt (gut!)
            pass

    return deprecated


# ═════════════════════════════════════════════════════════════════════════════
#  Trackingdienste
# ═════════════════════════════════════════════════════════════════════════════

def detect_trackers(domain: str) -> dict:
    """Scannt die Webseite auf externe Tracker und Cookie-Compliance-Tools."""
    print_progress("Privacy", "Tracker & Cookie-Banner erkennen …")
    result = {
        "trackers_found": [],
        "cookie_banner_found": [],
        "total_external_scripts": 0,
    }

    resp = http_get(f"https://{domain}", verify_ssl=False)
    if resp is None:
        resp = http_get(f"http://{domain}", verify_ssl=False)
    if resp is None:
        log.warning("  Webseite nicht erreichbar")
        return result

    html = resp.text.lower()

    # ── Tracker erkennen ──
    for tracker_name, signatures in config.TRACKER_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in html:
                result["trackers_found"].append({
                    "name": tracker_name,
                    "signature": sig,
                })
                log.info(f"  Tracker erkannt: {tracker_name}")
                break

    # ── Cookie-Banner erkennen ──
    for banner_sig in config.COOKIE_BANNER_SIGNATURES:
        if banner_sig in html:
            result["cookie_banner_found"].append(banner_sig)

    # ── Externe Skripte zählen ──
    from bs4 import BeautifulSoup
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
        external_scripts = [s for s in soup.find_all("script", src=True)
                           if not s["src"].startswith("/") and "://" in s["src"]
                           and domain not in s["src"]]
        result["total_external_scripts"] = len(external_scripts)
    except Exception:
        pass

    if result["cookie_banner_found"]:
        log.info(f"  Cookie-Banner erkannt: {', '.join(result['cookie_banner_found'])} ✓")
    elif result["trackers_found"]:
        log.warning("  Tracker vorhanden, aber KEIN Cookie-Banner erkannt ✗")

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  Sicherheitsheader
# ═════════════════════════════════════════════════════════════════════════════

def check_security_headers(domain: str) -> dict:
    """Prüft HTTP-Sicherheitsheader."""
    print_progress("Privacy", "Sicherheitsheader prüfen …")
    result = {"headers_present": {}, "headers_missing": [], "score": 0}

    resp = http_get(f"https://{domain}", verify_ssl=False)
    if resp is None:
        resp = http_get(f"http://{domain}", verify_ssl=False)
    if resp is None:
        log.warning("  Webseite nicht erreichbar")
        return result

    response_headers = {k.lower(): v for k, v in resp.headers.items()}

    for header in config.SECURITY_HEADERS:
        header_lower = header.lower()
        if header_lower in response_headers:
            value = response_headers[header_lower]
            assessment = _assess_header(header, value)
            result["headers_present"][header] = {
                "value": value,
                "assessment": assessment,
            }
        else:
            result["headers_missing"].append(header)

    # Score: Prozentsatz der vorhandenen Header
    total = len(config.SECURITY_HEADERS)
    present = len(result["headers_present"])
    result["score"] = round(present / total * 100) if total > 0 else 0

    log.info(f"  Sicherheitsheader-Score: {result['score']}% ({present}/{total})")
    return result


def _assess_header(header: str, value: str) -> str:
    """Bewertet einen Sicherheitsheader."""
    h = header.lower()
    v = value.lower()

    if h == "strict-transport-security":
        if "max-age" in v:
            max_age = re.search(r"max-age=(\d+)", v)
            if max_age:
                age = int(max_age.group(1))
                if age >= 31536000:
                    return "Gut (≥ 1 Jahr)"
                elif age >= 2592000:
                    return "Akzeptabel (≥ 30 Tage)"
                else:
                    return f"Zu kurz ({age}s)"
        return "Unvollständig"

    if h == "content-security-policy":
        if "unsafe-inline" in v:
            return "Warnung: unsafe-inline erlaubt"
        if "unsafe-eval" in v:
            return "Warnung: unsafe-eval erlaubt"
        return "Vorhanden"

    if h == "x-frame-options":
        if "deny" in v:
            return "Optimal (DENY)"
        if "sameorigin" in v:
            return "Gut (SAMEORIGIN)"
        return "Vorhanden"

    if h == "x-content-type-options":
        return "Gut (nosniff)" if "nosniff" in v else "Vorhanden"

    if h == "referrer-policy":
        safe_policies = ["no-referrer", "same-origin", "strict-origin",
                         "strict-origin-when-cross-origin"]
        if any(p in v for p in safe_policies):
            return "Gut"
        return "Schwach"

    return "Vorhanden"


# ═════════════════════════════════════════════════════════════════════════════
#  Reputation
# ═════════════════════════════════════════════════════════════════════════════

def check_reputation(domain: str) -> dict:
    """Prüft die Domain-Reputation über Google Safe Browsing und VirusTotal."""
    print_progress("Privacy", "Reputation / Safe-Browsing prüfen …")
    result = {
        "google_safe_browsing": {"checked": False, "safe": None, "threats": []},
        "virustotal": {"checked": False, "stats": {}},
    }

    # ── Google Safe Browsing ──
    gsb_key = config.API_KEYS.get("google_safebrowsing", "")
    if gsb_key:
        try:
            payload = {
                "client": {"clientId": "easm-scanner", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                    "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"https://{domain}"}, {"url": f"http://{domain}"}],
                },
            }
            import json
            resp = http_get(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}",
                timeout=10,
            )
            # Note: This should actually be a POST. Use requests directly.
            import requests as req
            resp = req.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}",
                json=payload, timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                result["google_safe_browsing"]["checked"] = True
                if data.get("matches"):
                    result["google_safe_browsing"]["safe"] = False
                    for match in data["matches"]:
                        result["google_safe_browsing"]["threats"].append({
                            "type": match.get("threatType", ""),
                            "platform": match.get("platformType", ""),
                        })
                    log.warning(f"  Google Safe Browsing: {len(data['matches'])} Bedrohungen! ✗")
                else:
                    result["google_safe_browsing"]["safe"] = True
                    log.info("  Google Safe Browsing: sauber ✓")
        except Exception as exc:
            log.debug(f"Google Safe Browsing fehlgeschlagen: {exc}")
    else:
        log.info("  Google Safe Browsing: kein API-Key (übersprungen)")

    # ── VirusTotal ──
    vt_key = config.API_KEYS.get("virustotal", "")
    if vt_key:
        try:
            resp = http_get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": vt_key},
            )
            if resp and resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                result["virustotal"]["checked"] = True
                result["virustotal"]["stats"] = stats
                result["virustotal"]["reputation"] = data.get("reputation", 0)
                result["virustotal"]["categories"] = data.get("categories", {})

                malicious = stats.get("malicious", 0)
                if malicious > 0:
                    log.warning(f"  VirusTotal: {malicious} Engine(s) melden Bedrohung ✗")
                else:
                    log.info("  VirusTotal: sauber ✓")
        except Exception as exc:
            log.debug(f"VirusTotal fehlgeschlagen: {exc}")
    else:
        log.info("  VirusTotal: kein API-Key (übersprungen)")

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  Hauptfunktion Modul 5
# ═════════════════════════════════════════════════════════════════════════════

def run(domain: str) -> dict:
    """Führt alle Datenschutz- & Reputations-Checks aus."""
    return {
        "web_tls": check_web_tls(domain),
        "trackers": detect_trackers(domain),
        "security_headers": check_security_headers(domain),
        "reputation": check_reputation(domain),
    }
