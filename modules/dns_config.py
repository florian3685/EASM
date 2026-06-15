"""
EASM Scanner — Modul 3: DNS-Konfiguration
===========================================
WHOIS/Registrar, CAA, A-Records, DNSSEC, Zone-Transfer.
"""

import dns.query
import dns.resolver
import dns.zone
import dns.dnssec
import dns.rdatatype
import dns.message
import dns.name

import config
from utils import get_logger, print_progress

log = get_logger("easm.dns_config")


# ═════════════════════════════════════════════════════════════════════════════
#  Administrative Sicherheit
# ═════════════════════════════════════════════════════════════════════════════

def check_whois_protection(domain: str) -> dict:
    """Prüft WHOIS-Daten auf clientTransferProhibited und weitere Schutzmechanismen."""
    print_progress("DNS Config", "WHOIS / Registrar-Daten prüfen …")
    result = {
        "registrar": "",
        "creation_date": "",
        "expiration_date": "",
        "updated_date": "",
        "status": [],
        "client_transfer_prohibited": False,
        "nameservers": [],
        "dnssec": "",
    }

    try:
        import whois
        w = whois.whois(domain)

        result["registrar"] = w.registrar or ""
        result["creation_date"] = str(w.creation_date) if w.creation_date else ""
        result["expiration_date"] = str(w.expiration_date) if w.expiration_date else ""
        result["updated_date"] = str(w.updated_date) if w.updated_date else ""
        result["nameservers"] = w.name_servers if w.name_servers else []

        # Status-Felder
        status = w.status if w.status else []
        if isinstance(status, str):
            status = [status]
        result["status"] = status

        # clientTransferProhibited prüfen
        result["client_transfer_prohibited"] = any(
            "clienttransferprohibited" in s.lower() for s in status
        )

        if result["client_transfer_prohibited"]:
            log.info("  clientTransferProhibited gesetzt ✓")
        else:
            log.warning("  clientTransferProhibited NICHT gesetzt ✗")

    except ImportError:
        log.warning("python-whois nicht installiert")
    except Exception as exc:
        log.warning(f"WHOIS-Abfrage fehlgeschlagen: {exc}")

    return result


def check_caa_records(domain: str) -> dict:
    """Prüft CAA-Records (Certificate Authority Authorization)."""
    print_progress("DNS Config", "CAA-Records prüfen …")
    result = {"records": [], "has_caa": False}

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    try:
        answers = resolver.resolve(domain, "CAA")
        for rdata in answers:
            result["records"].append({
                "flags": rdata.flags,
                "tag": rdata.tag.decode() if isinstance(rdata.tag, bytes) else str(rdata.tag),
                "value": rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value),
            })
        result["has_caa"] = True
        log.info(f"  {len(result['records'])} CAA-Records gefunden ✓")
    except dns.resolver.NoAnswer:
        log.warning("  Keine CAA-Records vorhanden ✗")
    except dns.resolver.NXDOMAIN:
        log.warning("  Domain nicht gefunden")
    except Exception as exc:
        log.debug(f"CAA-Abfrage fehlgeschlagen: {exc}")

    return result


def check_a_record(domain: str) -> dict:
    """Prüft, ob die Hauptdomain (ohne www) einen A-Record hat."""
    print_progress("DNS Config", "A-Record auf Hauptdomain prüfen …")
    result = {"has_a_record": False, "a_records": []}

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    try:
        answers = resolver.resolve(domain, "A")
        result["a_records"] = [str(r) for r in answers]
        result["has_a_record"] = True
        log.info(f"  A-Records auf {domain}: {', '.join(result['a_records'])} ✓")
    except Exception:
        log.info(f"  Kein A-Record auf {domain}")

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  Operative Sicherheit
# ═════════════════════════════════════════════════════════════════════════════

def check_dnssec(domain: str) -> dict:
    """Prüft die DNSSEC-Implementierung."""
    print_progress("DNS Config", "DNSSEC-Validierung …")
    result = {
        "enabled": False,
        "dnskey_found": False,
        "rrsig_found": False,
        "validation": "nicht geprüft",
        "details": "",
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    # DNSKEY prüfen
    try:
        answers = resolver.resolve(domain, "DNSKEY")
        result["dnskey_found"] = True
        result["details"] = f"{len(list(answers))} DNSKEY-Records gefunden"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception:
        pass

    # RRSIG prüfen (signierte Records)
    try:
        # DO-Bit setzen (DNSSEC OK)
        qname = dns.name.from_text(domain)
        request = dns.message.make_query(qname, dns.rdatatype.A, want_dnssec=True)
        # An den ersten Nameserver des Systems senden
        response = dns.query.udp(request, resolver.nameservers[0], timeout=config.DNS_TIMEOUT)

        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                result["rrsig_found"] = True
                break
    except Exception as exc:
        log.debug(f"DNSSEC-RRSIG-Check fehlgeschlagen: {exc}")

    if result["dnskey_found"] and result["rrsig_found"]:
        result["enabled"] = True
        result["validation"] = "DNSSEC aktiv (DNSKEY + RRSIG vorhanden)"
        log.info("  DNSSEC aktiv ✓")
    elif result["dnskey_found"]:
        result["enabled"] = True
        result["validation"] = "DNSKEY vorhanden, RRSIG nicht bestätigt"
        log.warning("  DNSSEC teilweise konfiguriert ⚠")
    else:
        result["validation"] = "DNSSEC nicht implementiert"
        log.warning("  DNSSEC nicht implementiert ✗")

    return result


def check_zone_transfer(domain: str) -> dict:
    """
    Versucht einen DNS-Zonentransfer (AXFR) gegen alle Nameserver.
    Ein erfolgreicher Transfer ist ein Sicherheitsrisiko!
    """
    print_progress("DNS Config", "Zonentransfer-Test (AXFR) …")
    result = {"vulnerable_ns": [], "safe_ns": [], "error_ns": []}

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    try:
        ns_answers = resolver.resolve(domain, "NS")
    except Exception:
        log.warning("  NS-Auflösung fehlgeschlagen")
        return result

    for rdata in ns_answers:
        ns_hostname = str(rdata.target).rstrip(".")
        try:
            # IP des Nameservers auflösen
            ns_ips = resolver.resolve(ns_hostname, "A")
            for ns_ip in ns_ips:
                ns_ip_str = str(ns_ip)
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip_str, domain, timeout=config.DNS_TIMEOUT)
                    )
                    # Wenn wir hier ankommen, war der Transfer erfolgreich!
                    record_count = sum(1 for _ in zone.nodes)
                    result["vulnerable_ns"].append({
                        "nameserver": ns_hostname,
                        "ip": ns_ip_str,
                        "records_exposed": record_count,
                    })
                    log.critical(f"  ⚠ ZONENTRANSFER MÖGLICH bei {ns_hostname} ({ns_ip_str})! {record_count} Records exponiert!")
                except dns.xfr.TransferError:
                    result["safe_ns"].append(ns_hostname)
                except Exception:
                    result["safe_ns"].append(ns_hostname)
        except Exception as exc:
            result["error_ns"].append({"nameserver": ns_hostname, "error": str(exc)})

    if not result["vulnerable_ns"]:
        log.info("  Kein Zonentransfer möglich ✓")

    return result


def check_typosquatting(domain: str) -> list[dict]:
    """Prüft auf registrierte Phishing-/Typosquatting-Domains via dnstwist."""
    print_progress("DNS Config", "Brand Protection (Typosquatting) …")
    import subprocess
    import json
    
    results = []
    try:
        # Führt dnstwist aus, gibt nur registrierte Domains (-r) als JSON (-f json) zurück
        # Wir limitieren das Dictionary (-m) um die Laufzeit in Grenzen zu halten, falls das Tool zu lange braucht.
        # Aber im automatisierten CLI reicht normaler Run.
        cmd = ["dnstwist", "--format", "json", "--registered", domain]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if p.returncode == 0 and p.stdout.strip():
            try:
                data = json.loads(p.stdout)
                for item in data:
                    if item.get("domain-name") != domain:
                        results.append({
                            "domain": item.get("domain-name"),
                            "fuzzer": item.get("fuzzer", ""),
                            "dns_a": item.get("dns-a", []),
                            "dns_ns": item.get("dns-ns", []),
                            "dns_mx": item.get("dns-mx", []),
                        })
            except json.JSONDecodeError:
                log.warning("dnstwist JSON Parse-Fehler")
                
        if results:
            log.warning(f"  {len(results)} potenziell betrügerische Typosquatting-Domains entdeckt!")
        else:
            log.info("  Keine registrierten Typosquatting-Domains gefunden.")
            
    except FileNotFoundError:
        log.warning("dnstwist nicht gefunden. (pip install dnstwist)")
    except subprocess.TimeoutExpired:
        log.warning("dnstwist Timeout")
    except Exception as exc:
        log.debug(f"dnstwist Fehler: {exc}")
        
    return results


# ═════════════════════════════════════════════════════════════════════════════
#  Hauptfunktion Modul 3
# ═════════════════════════════════════════════════════════════════════════════

def run(domain: str) -> dict:
    """Führt alle DNS-Konfigurations-Checks aus."""
    return {
        "administrative_security": {
            "whois_protection": check_whois_protection(domain),
            "caa_records": check_caa_records(domain),
            "a_record_main_domain": check_a_record(domain),
        },
        "operative_security": {
            "dnssec": check_dnssec(domain),
            "zone_transfer": check_zone_transfer(domain),
        },
        "brand_protection": {
            "typosquatting": check_typosquatting(domain)
        }
    }
