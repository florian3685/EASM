"""
EASM Scanner — Modul 2: Infrastrukturstabilität
=================================================
DNS-/Mail-Diversifikation, CDN/WAF-Erkennung, Anycast-Check, TTL-Analyse.
"""

import dns.resolver

import config
from utils import (get_logger, http_get, http_head, resolve_hostname,
                   get_asn_info, print_progress)

log = get_logger("easm.infrastructure")

# ── Öffentliche DNS-Resolver für Anycast-Vergleich ──
PUBLIC_RESOLVERS = [
    "8.8.8.8",        # Google
    "1.1.1.1",        # Cloudflare
    "9.9.9.9",        # Quad9
    "208.67.222.222",  # OpenDNS
]


def check_dns_diversification(domain: str) -> dict:
    """
    Prüft die Verteilung der Nameserver auf verschiedene IP-Netze, ASNs und Standorte.
    """
    print_progress("Infrastructure", "DNS-Diversifikation prüfen …")
    result = {
        "nameservers": [],
        "unique_asns": [],
        "unique_cidrs": [],
        "unique_countries": [],
        "diversification_score": "LOW",
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    try:
        ns_answers = resolver.resolve(domain, "NS")
    except Exception as exc:
        log.warning(f"NS-Auflösung fehlgeschlagen: {exc}")
        return result

    asns = set()
    cidrs = set()
    countries = set()

    for rdata in ns_answers:
        ns_hostname = str(rdata.target).rstrip(".")
        ips = resolve_hostname(ns_hostname)
        ns_entry = {
            "hostname": ns_hostname,
            "ips": ips,
            "asn_info": [],
        }

        for ip in ips:
            info = get_asn_info(ip)
            ns_entry["asn_info"].append(info)
            if info["asn"]:
                asns.add(info["asn"])
            if info["network_cidr"]:
                cidrs.add(info["network_cidr"])
            if info["asn_country_code"]:
                countries.add(info["asn_country_code"])

        result["nameservers"].append(ns_entry)

    result["unique_asns"] = list(asns)
    result["unique_cidrs"] = list(cidrs)
    result["unique_countries"] = list(countries)

    # DDoS-Resilienz-Score
    ns_count = len(result["nameservers"])
    if ns_count >= 3 and len(asns) >= 2 and len(countries) >= 2:
        result["diversification_score"] = "HIGH"
    elif ns_count >= 2 and len(asns) >= 2:
        result["diversification_score"] = "MEDIUM"
    else:
        result["diversification_score"] = "LOW"

    log.info(f"DNS-Diversifikation: {ns_count} NS, {len(asns)} ASNs, {len(countries)} Länder → {result['diversification_score']}")
    return result


def check_mail_diversification(domain: str) -> dict:
    """
    Prüft die Verteilung der Mailserver auf verschiedene IP-Netze, ASNs und Standorte.
    """
    print_progress("Infrastructure", "Mail-Diversifikation prüfen …")
    result = {
        "mx_servers": [],
        "unique_asns": [],
        "unique_cidrs": [],
        "unique_countries": [],
        "diversification_score": "LOW",
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    try:
        mx_answers = resolver.resolve(domain, "MX")
    except Exception as exc:
        log.warning(f"MX-Auflösung fehlgeschlagen: {exc}")
        return result

    asns = set()
    cidrs = set()
    countries = set()

    for rdata in sorted(mx_answers, key=lambda r: r.preference):
        mx_hostname = str(rdata.exchange).rstrip(".")
        ips = resolve_hostname(mx_hostname)
        mx_entry = {
            "hostname": mx_hostname,
            "priority": rdata.preference,
            "ips": ips,
            "asn_info": [],
        }

        for ip in ips:
            info = get_asn_info(ip)
            mx_entry["asn_info"].append(info)
            if info["asn"]:
                asns.add(info["asn"])
            if info["network_cidr"]:
                cidrs.add(info["network_cidr"])
            if info["asn_country_code"]:
                countries.add(info["asn_country_code"])

        result["mx_servers"].append(mx_entry)

    result["unique_asns"] = list(asns)
    result["unique_cidrs"] = list(cidrs)
    result["unique_countries"] = list(countries)

    mx_count = len(result["mx_servers"])
    if mx_count >= 3 and len(asns) >= 2:
        result["diversification_score"] = "HIGH"
    elif mx_count >= 2 and len(asns) >= 2:
        result["diversification_score"] = "MEDIUM"
    else:
        result["diversification_score"] = "LOW"

    log.info(f"Mail-Diversifikation: {mx_count} MX, {len(asns)} ASNs → {result['diversification_score']}")
    return result


def _run_wafw00f(domain: str) -> list[dict]:
    """Prüft die Web Application Firewall mit wafw00f."""
    import subprocess
    import tempfile
    import json
    import os
    
    results = []
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_file = tf.name
            
        # Wähle das Standard-Schema
        cmd = ["wafw00f", f"https://{domain}", "-a", "-o", out_file]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        
        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            with open(out_file, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    results = data
        
        if os.path.exists(out_file):
            os.remove(out_file)
            
    except FileNotFoundError:
        log.warning("wafw00f nicht gefunden (pip install wafw00f).")
    except subprocess.TimeoutExpired:
        log.warning("wafw00f Scan in Timeout gelaufen.")
    except Exception as exc:
        log.debug(f"wafw00f Fehler: {exc}")
        
    return results


def check_web_protections(domain: str) -> dict:
    """
    Erkennt CDNs, WAFs, Anycast-Routing und analysiert DNS-TTL-Werte.
    """
    print_progress("Infrastructure", "Web-Schutzmaßnahmen analysieren …")
    result = {
        "cdn_waf_detected": [],
        "wafw00f_scan": [],
        "anycast": {"likely": False, "details": []},
        "ttl_analysis": {},
    }

    # ── CDN / WAF Detection via HTTP-Header ──
    for scheme in ("https", "http"):
        resp = http_head(f"{scheme}://{domain}")
        if resp is None:
            continue

        headers = {k.lower(): v for k, v in resp.headers.items()}

        for provider, signatures in config.CDN_WAF_HEADERS.items():
            for sig in signatures:
                if sig.lower() in headers:
                    result["cdn_waf_detected"].append({
                        "provider": provider,
                        "header": sig,
                        "value": headers[sig.lower()],
                    })

        # Server-Header als Hinweis
        server = headers.get("server", "").lower()
        if "cloudflare" in server:
            result["cdn_waf_detected"].append({"provider": "Cloudflare", "header": "server", "value": server})
        elif "akamaighost" in server:
            result["cdn_waf_detected"].append({"provider": "Akamai", "header": "server", "value": server})

        break  # Nur ein Schema

    # Deduplizieren
    seen = set()
    deduped = []
    for item in result["cdn_waf_detected"]:
        key = item["provider"]
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    result["cdn_waf_detected"] = deduped
    
    # ── WAF-Fingerprinting (wafw00f) ──
    result["wafw00f_scan"] = _run_wafw00f(domain)

    # ── Anycast Detection ──
    result["anycast"] = _check_anycast(domain)

    # ── TTL-Analyse ──
    result["ttl_analysis"] = _analyze_ttl(domain)

    if result["cdn_waf_detected"] or result["wafw00f_scan"]:
        log.info(f"CDN/WAF erkannt: {len(result['cdn_waf_detected'])} via Header, {len(result['wafw00f_scan'])} via wafw00f")
    else:
        log.info("Kein CDN/WAF erkannt")

    return result


def _check_anycast(domain: str) -> dict:
    """
    Prüft Anycast durch Abfrage bei mehreren öffentlichen Resolvern.
    Unterschiedliche IPs deuten auf Anycast oder GeoDNS hin.
    """
    result = {"likely": False, "details": []}
    resolved_ips = set()

    for resolver_ip in PUBLIC_RESOLVERS:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.timeout = config.DNS_TIMEOUT
            resolver.lifetime = config.DNS_TIMEOUT
            answers = resolver.resolve(domain, "A")
            ips = sorted(str(r) for r in answers)
            resolved_ips.update(ips)
            result["details"].append({"resolver": resolver_ip, "ips": ips})
        except Exception:
            result["details"].append({"resolver": resolver_ip, "ips": [], "error": "Auflösung fehlgeschlagen"})

    # Wenn verschiedene Resolver verschiedene IPs zurückgeben → Anycast wahrscheinlich
    all_ips = set()
    for d in result["details"]:
        all_ips.update(d.get("ips", []))

    if len(all_ips) > 1:
        result["likely"] = True
        log.info(f"Anycast wahrscheinlich: {len(all_ips)} verschiedene IPs von {len(PUBLIC_RESOLVERS)} Resolvern")

    return result


def _analyze_ttl(domain: str) -> dict:
    """Analysiert die TTL-Werte der DNS-Records."""
    result = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    for rdtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = resolver.resolve(domain, rdtype)
            ttl = answers.rrset.ttl
            result[rdtype] = {
                "ttl_seconds": ttl,
                "assessment": (
                    "sehr niedrig (< 60s, Failover-fähig)" if ttl < 60
                    else "niedrig (< 300s, schnelles Failover)" if ttl < 300
                    else "normal (300-3600s)" if ttl <= 3600
                    else "hoch (> 3600s, langsames Failover)"
                ),
            }
        except Exception:
            pass

    return result


def _shodan_origin_leak(domain: str) -> list[dict]:
    """Sucht über Shodan passiv nach Origin-IP-Leaks unter Umgehung von WAFs."""
    print_progress("Infrastructure", "Shodan Origin-IP Tracking (WAF-Bypass) …")
    leaks = []
    api_key = config.API_KEYS.get("shodan", "")
    if not api_key:
        return leaks
        
    try:
        import shodan
        api = shodan.Shodan(api_key)
        # Suche nach allen Hosts, deren SSL-Zertifikat den Domain-Namen enthält
        query = f'ssl:"{domain}"'
        results = api.search(query, limit=10)
        
        # WAF/CDN Netzwerke filtern
        waf_asns = ["cloudflare", "akamai", "fastly", "incapsula", "sucuri", "amazon", "microsoft"]
        
        for match in results.get("matches", []):
            ip = match.get("ip_str")
            org = str(match.get("org", "")).lower()
            isp = str(match.get("isp", "")).lower()
            
            # Ist die gefundene IP wirklich Origin oder nur ein CDN Node?
            is_waf = any(waf in org for waf in waf_asns) or any(waf in isp for waf in waf_asns)
            
            if not is_waf:
                leaks.append({
                    "ip": ip,
                    "organization": match.get("org", ""),
                    "isp": match.get("isp", ""),
                    "port": match.get("port", ""),
                    "assessment": "CRITICAL ORIGIN LEAK (WAF Bypass möglich)"
                })
                log.critical(f"  🔴 ORIGIN-IP LEAK ENTDECKT: {ip} ({match.get('org')}) - WAF BYPASS MÖGLICH!")
                
    except ImportError:
        log.warning("shodan Bibliothek nicht installiert (pip install shodan)")
    except Exception as exc:
        log.debug(f"Shodan API Fehler: {exc}")
        
    if not leaks and api_key:
         log.info("  Keine Origin-IP Leaks über Shodan gefunden.")
         
    return leaks


def check_bgp_hijacking(domain: str) -> list[dict]:
    """Prüft die IPs der Domain auf fehlende BGP RPKI ROA (Route Origin Authorization)."""
    print_progress("Infrastructure", "BGP Hijacking RPKI ROA Check …")
    risks = []
    
    ips = resolve_hostname(domain)
    # Check MX too
    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT
    try:
        mx_answers = resolver.resolve(domain, "MX")
        for rdata in mx_answers:
            mx_hostname = str(rdata.exchange).rstrip(".")
            ips.extend(resolve_hostname(mx_hostname))
    except Exception:
        pass
        
    ips = list(set(ips))
    checked_cidrs = set()
    
    for ip in ips:
        info = get_asn_info(ip)
        asn = info.get("asn", "")
        cidr = info.get("network_cidr", "")
        
        if not asn or not cidr or cidr in checked_cidrs:
            continue
            
        checked_cidrs.add(cidr)
        asn_clean = str(asn).replace("AS", "")
        
        try:
            # Cloudflare RPKI API: https://rpki.cloudflare.com/api/v1/validity/AS<ASN>/<prefix>
            # returns {"validated_route":{"validity":{"state":"valid|invalid|not-found"}}}
            url = f"https://rpki.cloudflare.com/api/v1/validity/AS{asn_clean}/{cidr}"
            resp = http_get(url, timeout=5)
            if resp and resp.status_code == 200:
                data = resp.json()
                state = data.get("validated_route", {}).get("validity", {}).get("state", "not-found")
                
                if state == "not-found" or state == "invalid":
                    risks.append({
                        "ip": ip,
                        "asn": f"AS{asn_clean}",
                        "cidr": cidr,
                        "rpki_state": state,
                        "assessment": "CRITICAL: BGP ROUTE HIJACKING POSSIBLE (Missing ROA)"
                    })
                    log.critical(f"  🔴 BGP HIJACKING GEFAHR: {cidr} (AS{asn_clean}) hat State '{state}'!")
                else:
                    log.info(f"  BGP ROA Valid: {cidr} (AS{asn_clean}) ✓")
        except Exception as exc:
            log.debug(f"RPKI Abfragefehler für {cidr}: {exc}")

    return risks


# ═════════════════════════════════════════════════════════════════════════════
#  Hauptfunktion Modul 2
# ═════════════════════════════════════════════════════════════════════════════

def run(domain: str) -> dict:
    """Führt alle Scans des Moduls 'Infrastrukturstabilität' aus."""
    return {
        "dns_diversification": check_dns_diversification(domain),
        "mail_diversification": check_mail_diversification(domain),
        "bgp_hijacking_risks": check_bgp_hijacking(domain),
        "web_protections": check_web_protections(domain),
        "origin_ip_leaks": _shodan_origin_leak(domain),
    }
