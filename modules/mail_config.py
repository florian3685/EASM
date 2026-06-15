"""
EASM Scanner — Modul 4: Mailkonfiguration
============================================
TLS-Prüfung der Mailserver, SPF/DKIM/DMARC-Validierung, Mail-Blacklists.
"""

import re
import socket
import ssl
from datetime import datetime, timezone

import dns.resolver

import config
from utils import (get_logger, resolve_hostname, check_dnsbl,
                   print_progress, ip_to_reverse)

log = get_logger("easm.mail_config")


# ═════════════════════════════════════════════════════════════════════════════
#  Mail-Verschlüsselung (TLS)
# ═════════════════════════════════════════════════════════════════════════════

def check_mail_tls(domain: str) -> list[dict]:
    """
    Deep-Scan der TLS-Konfiguration auf allen Mailservern.
    Verbindet per STARTTLS und analysiert das Zertifikat.
    """
    print_progress("Mail Config", "Mail-TLS prüfen …")
    results = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    try:
        mx_answers = resolver.resolve(domain, "MX")
    except Exception as exc:
        log.warning(f"MX-Auflösung fehlgeschlagen: {exc}")
        return results

    for rdata in sorted(mx_answers, key=lambda r: r.preference):
        mx_hostname = str(rdata.exchange).rstrip(".")
        mx_result = {
            "hostname": mx_hostname,
            "priority": rdata.preference,
            "starttls_supported": False,
            "tls_version": "",
            "cipher_suite": "",
            "certificate": {},
            "errors": [],
        }

        try:
            import smtplib
            
            # ISP blockiert oft Port 25 (Network is unreachable oder timeout).
            # Fallback auf Submission-Port 587, um TLS-Zertifikat dennoch prüfen zu können.
            # Nutzung der reinen IPv4-Adresse zur Vermeidung von IPv6-Timeout "Network is unreachable"
            ips = resolve_hostname(mx_hostname)
            target_ip = ips[0] if ips else mx_hostname
            
            server = None
            try:
                server = smtplib.SMTP(target_ip, 25, timeout=config.TIMEOUT)
            except Exception:
                server = smtplib.SMTP(target_ip, 587, timeout=config.TIMEOUT)
                
            with server:
                server.ehlo("scanner.local")
                
                if server.has_extn("STARTTLS"):
                    from utils import get_advanced_ssl_context
                    context = get_advanced_ssl_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    server.starttls(context=context)
                    tls_sock = server.sock
                    
                    mx_result["starttls_supported"] = True
                    mx_result["tls_version"] = tls_sock.version()
                    mx_result["cipher_suite"] = tls_sock.cipher()[0] if tls_sock.cipher() else ""

                    # Zertifikat analysieren
                    cert_bin = tls_sock.getpeercert(binary_form=True)
                    if cert_bin:
                        from cryptography import x509
                        cert = x509.load_der_x509_certificate(cert_bin)
                        mx_result["certificate"] = {
                            "subject": cert.subject.rfc4514_string(),
                            "issuer": cert.issuer.rfc4514_string(),
                            "not_before": cert.not_valid_before_utc.isoformat(),
                            "not_after": cert.not_valid_after_utc.isoformat(),
                            "serial_number": str(cert.serial_number),
                            "key_size": cert.public_key().key_size if hasattr(cert.public_key(), "key_size") else None,
                            "is_expired": cert.not_valid_after_utc < datetime.now(timezone.utc),
                        }

                    log.info(f"  {mx_hostname}: STARTTLS ✓ ({mx_result['tls_version']})")
                else:
                    mx_result["errors"].append("STARTTLS nicht unterstützt")
                    log.warning(f"  {mx_hostname}: STARTTLS nicht unterstützt ✗")

        except Exception as exc:
            mx_result["errors"].append(str(exc))
            log.warning(f"  {mx_hostname}: TLS-Check fehlgeschlagen ({exc})")

        results.append(mx_result)

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  SPF / DKIM / DMARC
# ═════════════════════════════════════════════════════════════════════════════

def check_spf(domain: str) -> dict:
    """Prüft SPF-Record auf Vorhandensein und korrekte Konfiguration."""
    print_progress("Mail Config", "SPF prüfen …")
    result = {
        "has_spf": False,
        "record": "",
        "mechanism": "",
        "all_qualifier": "",
        "issues": [],
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.lower().startswith("v=spf1"):
                result["has_spf"] = True
                result["record"] = txt

                # all-Mechanismus analysieren
                if "-all" in txt:
                    result["all_qualifier"] = "-all (strict, empfohlen)"
                elif "~all" in txt:
                    result["all_qualifier"] = "~all (softfail)"
                    result["issues"].append("SPF nutzt ~all statt -all (softfail erlaubt Zustellung)")
                elif "?all" in txt:
                    result["all_qualifier"] = "?all (neutral, unsicher)"
                    result["issues"].append("SPF nutzt ?all — bietet keinen effektiven Schutz")
                elif "+all" in txt:
                    result["all_qualifier"] = "+all (GEFÄHRLICH!)"
                    result["issues"].append("SPF nutzt +all — erlaubt JEDEM E-Mails im Namen der Domain zu senden!")

                # Zu viele DNS-Lookups?
                lookup_count = len(re.findall(r'\b(include:|a:|mx:|ptr:|exists:)', txt))
                if lookup_count > 10:
                    result["issues"].append(f"SPF enthält {lookup_count} DNS-Lookups (max. 10 erlaubt)")

                log.info(f"  SPF: {result['all_qualifier']} ✓" if result['all_qualifier'].startswith('-') else f"  SPF: {result['all_qualifier']} ⚠")
                break
    except Exception:
        pass

    if not result["has_spf"]:
        result["issues"].append("Kein SPF-Record vorhanden")
        log.warning("  SPF: nicht vorhanden ✗")

    return result


def check_dkim(domain: str) -> dict:
    """Prüft DKIM-Records für bekannte Selektoren."""
    print_progress("Mail Config", "DKIM prüfen …")
    result = {"found_selectors": [], "has_dkim": False}

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    for selector in config.DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = resolver.resolve(dkim_domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=DKIM1" in txt or "p=" in txt:
                    result["found_selectors"].append({
                        "selector": selector,
                        "record": txt[:200],
                    })
                    result["has_dkim"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except Exception:
            continue

    if result["has_dkim"]:
        log.info(f"  DKIM: {len(result['found_selectors'])} Selektor(en) gefunden ✓")
    else:
        log.warning("  DKIM: kein Selektor gefunden ✗")

    return result


def check_dmarc(domain: str) -> dict:
    """Prüft DMARC-Record auf Vorhandensein und Policy-Stärke."""
    print_progress("Mail Config", "DMARC prüfen …")
    result = {
        "has_dmarc": False,
        "record": "",
        "policy": "",
        "subdomain_policy": "",
        "rua": "",
        "ruf": "",
        "issues": [],
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.lower().startswith("v=dmarc1"):
                result["has_dmarc"] = True
                result["record"] = txt

                # Policy
                p_match = re.search(r'p=(\w+)', txt, re.IGNORECASE)
                if p_match:
                    policy = p_match.group(1).lower()
                    result["policy"] = policy
                    if policy == "none":
                        result["issues"].append("DMARC-Policy ist 'none' — nur Monitoring, kein Schutz")
                    elif policy == "quarantine":
                        result["issues"].append("DMARC-Policy ist 'quarantine' — E-Mails werden markiert, nicht abgelehnt")

                # Subdomain policy
                sp_match = re.search(r'sp=(\w+)', txt, re.IGNORECASE)
                if sp_match:
                    result["subdomain_policy"] = sp_match.group(1).lower()

                # Reporting
                rua_match = re.search(r'rua=([^;]+)', txt, re.IGNORECASE)
                if rua_match:
                    result["rua"] = rua_match.group(1)
                ruf_match = re.search(r'ruf=([^;]+)', txt, re.IGNORECASE)
                if ruf_match:
                    result["ruf"] = ruf_match.group(1)

                if result["policy"] == "reject":
                    log.info("  DMARC: reject ✓")
                else:
                    log.warning(f"  DMARC: {result['policy']} ⚠")
                break
    except Exception:
        pass

    if not result["has_dmarc"]:
        result["issues"].append("Kein DMARC-Record vorhanden")
        log.warning("  DMARC: nicht vorhanden ✗")

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  Mail-Blacklists
# ═════════════════════════════════════════════════════════════════════════════

def check_mail_blacklists(domain: str) -> list[dict]:
    """Prüft alle MX-Server-IPs gegen gängige E-Mail-Blacklists."""
    print_progress("Mail Config", "Mail-Blacklists prüfen …")
    results = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    try:
        mx_answers = resolver.resolve(domain, "MX")
    except Exception:
        log.warning("MX-Auflösung fehlgeschlagen")
        return results

    for rdata in mx_answers:
        mx_hostname = str(rdata.exchange).rstrip(".")
        ips = resolve_hostname(mx_hostname)

        for ip in ips:
            # Nur IPv4
            if ":" in ip:
                continue
            ip_result = {
                "mx_hostname": mx_hostname,
                "ip": ip,
                "listed_on": [],
            }

            for bl in config.MAIL_DNSBLS:
                if check_dnsbl(ip, bl):
                    ip_result["listed_on"].append(bl)
                    log.warning(f"  {ip} ({mx_hostname}) auf Blacklist: {bl}")

            if not ip_result["listed_on"]:
                log.info(f"  {ip} ({mx_hostname}): sauber ✓")

            results.append(ip_result)

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  Hauptfunktion Modul 4
# ═════════════════════════════════════════════════════════════════════════════

def run(domain: str) -> dict:
    """Führt alle Mail-Konfigurations-Checks aus."""
    return {
        "mail_tls": check_mail_tls(domain),
        "spf": check_spf(domain),
        "dkim": check_dkim(domain),
        "dmarc": check_dmarc(domain),
        "mail_blacklists": check_mail_blacklists(domain),
    }
