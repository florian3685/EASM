"""
EASM Scanner — Modul 1: Angriffsoberfläche (Attack Surface)
=============================================================
Host-Discovery, Port-Scanning, Software-Erkennung, CVE-Abgleich,
Login-Erkennung und Blacklist-Prüfung.
"""

import json
import re
import socket
import subprocess
import tempfile
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import dns.resolver
import requests

import config
from utils import (get_logger, http_get, resolve_hostname, reverse_dns,
                   check_dnsbl, get_asn_info, print_progress)

log = get_logger("easm.attack_surface")

# ═════════════════════════════════════════════════════════════════════════════
#  Host-Discovery
# ═════════════════════════════════════════════════════════════════════════════

def discover_hosts(domain: str) -> dict:
    """
    Identifiziert alle erreichbaren IPs und Subdomains.
    Nutzt DNS-Auflösung und Certificate Transparency (crt.sh).
    """
    print_progress("Attack Surface", "Host-Discovery gestartet …")
    results = {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "subdomains": [],
        "hosts": [],  # list of {ip, hostname, roles}
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    # ── A / AAAA Records ──
    for rdtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(domain, rdtype)
            for rdata in answers:
                key = "a_records" if rdtype == "A" else "aaaa_records"
                results[key].append(str(rdata))
        except Exception:
            pass

    # ── Subdomain-Enumeration (Multi-Source Engine) ──
    from modules.subdomain_enum import enumerate_all
    enum_result = enumerate_all(domain, bruteforce=True, permute=True, validate=True)
    results["subdomains"] = enum_result["subdomains"]
    results["subdomain_sources"] = enum_result["sources"]
    results["subdomain_wildcard"] = enum_result["wildcard"]

    # ── Hosts zusammenführen & Rollen zuweisen ──
    all_hostnames = [domain, f"www.{domain}"] + results["subdomains"]
    seen_ips = set()

    # MX-Server ermitteln
    mx_hosts = set()
    try:
        mx_answers = resolver.resolve(domain, "MX")
        for rdata in mx_answers:
            mx_hosts.add(str(rdata.exchange).rstrip(".").lower())
    except Exception:
        pass

    # NS-Server ermitteln
    ns_hosts = set()
    try:
        ns_answers = resolver.resolve(domain, "NS")
        for rdata in ns_answers:
            ns_hosts.add(str(rdata.target).rstrip(".").lower())
    except Exception:
        pass

    for hostname in all_hostnames:
        hostname = hostname.strip().lower().rstrip(".")
        if not hostname or not hostname.endswith(domain):
            continue
        ips = resolve_hostname(hostname)
        for ip in ips:
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            # Rollenklassifizierung
            roles = _classify_host_roles(hostname, ip, mx_hosts, ns_hosts)
            results["hosts"].append({
                "ip": ip,
                "hostname": hostname,
                "roles": roles,
            })

    log.info(f"Host-Discovery abgeschlossen: {len(results['hosts'])} Hosts, {len(results['subdomains'])} Subdomains")
    return results


def _classify_host_roles(hostname: str, ip: str, mx_hosts: set, ns_hosts: set) -> list[str]:
    """Klassifiziert einen Host nach seiner Rolle."""
    roles = []
    hn = hostname.lower()

    # Web
    if any(kw in hn for kw in ("www", "web", "cdn", "static", "app", "api")):
        roles.append("WEB")
    elif hn.count(".") == 1:  # Hauptdomain
        roles.append("WEB")

    # Mail
    if hn in mx_hosts or any(kw in hn for kw in ("mail", "mx", "smtp", "imap", "pop")):
        roles.append("MAIL")

    # DNS
    if hn in ns_hosts or any(kw in hn for kw in ("ns", "dns")):
        roles.append("DNS")

    # Andere Server-Rollen
    if any(kw in hn for kw in ("vpn", "remote", "gateway", "fw", "firewall")):
        roles.append("VPN")
    if any(kw in hn for kw in ("ftp", "sftp", "file")):
        roles.append("FTP")
    if any(kw in hn for kw in ("db", "database", "sql", "mongo", "redis")):
        roles.append("DB")

    if not roles:
        roles.append("SRV")

    return roles


# ═════════════════════════════════════════════════════════════════════════════
#  Offene Zugänge (Port-Scanning)
# ═════════════════════════════════════════════════════════════════════════════

def scan_open_ports(hosts: list[dict], on_host_done=None) -> list[dict]:
    """
    Port-Scanning aller identifizierten Hosts.
    Versucht Masscan (als Root), sonst Nmap, sonst TCP-Connect.
    """
    print_progress("Attack Surface", "Port-Scanning gestartet …")
    results = []

    total_hosts = len(hosts)
    for index, host in enumerate(hosts, start=1):
        ip = host["ip"]
        hostname = host.get("hostname", ip)
        host_result = {
            "ip": ip,
            "hostname": hostname,
            "open_ports": [],
        }

        # Versuch 1: Masscan (schnell, erfordert root, scannt 1-65535)
        masscan_result = _masscan_scan(ip)
        if masscan_result is not None:
            host_result["open_ports"] = masscan_result
        else:
            # Versuch 2: Nmap-Scan (Standard Ports)
            nmap_result = _nmap_scan(ip)
            if nmap_result is not None:
                host_result["open_ports"] = nmap_result
            else:
                # Versuch 3: TCP-Connect-Scan (Fallback)
                host_result["open_ports"] = _tcp_connect_scan(ip)

        if host_result["open_ports"]:
            log.info(f"  {hostname} ({ip}): {len(host_result['open_ports'])} offene Ports")
        results.append(host_result)
        if on_host_done:
            on_host_done(results[:], index, total_hosts, host_result)

    return results


def _masscan_scan(ip: str) -> list[dict] | None:
    """Hyperspeed Port-Scan via masscan (1-65535). Erfordert Root-Rechte."""
    try:
        # Ohne Root kein Masscan
        if os.geteuid() != 0:
            return None
            
        with tempfile.NamedTemporaryFile("r", delete=False) as tf:
            out_file = tf.name
            
        # 10.000 Packete pro Sekunde!
        cmd = ["masscan", ip, "-p1-65535", "--rate=10000", "-oJ", out_file]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
        
        open_ports = []
        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            with open(out_file, "r") as f:
                data = json.load(f)
                for entry in data:
                    for port_info in entry.get("ports", []):
                        port = port_info.get("port")
                        open_ports.append({
                            "port": port,
                            "protocol": port_info.get("proto", "tcp"),
                            "state": "open",
                            "service": _guess_service(port),
                            "product": "",
                            "version": "",
                            "extra_info": "",
                            "cpe": "",
                            "category": _categorize_port(port),
                        })
        os.remove(out_file)
        return open_ports if open_ports else None
    except Exception:
        return None


def _nmap_scan(ip: str) -> list[dict] | None:
    """Nmap-basierter Port-Scan mit Service-Detection und Timeout."""
    try:
        import nmap
        nm = nmap.PortScanner()
        port_str = ",".join(str(p) for p in config.ALL_PORTS)
        # --host-timeout 60s verhindert, dass einzelne Hosts den Scan blockieren
        nm.scan(ip, port_str, arguments="-sV --version-intensity 2 -T4 --open --host-timeout 60s",
                timeout=90)

        open_ports = []
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port in sorted(nm[ip][proto].keys()):
                    info = nm[ip][proto][port]
                    if info["state"] == "open":
                        open_ports.append({
                            "port": port,
                            "protocol": proto,
                            "state": info["state"],
                            "service": info.get("name", ""),
                            "product": info.get("product", ""),
                            "version": info.get("version", ""),
                            "extra_info": info.get("extrainfo", ""),
                            "cpe": info.get("cpe", ""),
                            "category": _categorize_port(port),
                        })
        return open_ports
    except ImportError:
        log.warning("python-nmap nicht verfügbar, Fallback auf TCP-Connect")
        return None
    except Exception as exc:
        log.warning(f"Nmap-Scan fehlgeschlagen ({exc}), Fallback auf TCP-Connect")
        return None


def _tcp_connect_scan(ip: str) -> list[dict]:
    """Einfacher TCP-Connect-Scan als Fallback."""
    timeout = float(os.environ.get("EASM_TCP_CONNECT_TIMEOUT", "1.5"))
    workers = max(1, int(os.environ.get("EASM_TCP_SCAN_WORKERS", "32")))

    def check_port(port: int) -> dict | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = _grab_banner(sock, ip, port)
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": _guess_service(port),
                    "product": banner.get("product", ""),
                    "version": banner.get("version", ""),
                    "extra_info": "",
                    "cpe": "",
                    "category": _categorize_port(port),
                }
            sock.close()
        except Exception:
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return None

    open_ports = []
    max_workers = min(workers, len(config.ALL_PORTS))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_port, port) for port in config.ALL_PORTS]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda item: item["port"])


def _grab_banner(sock: socket.socket, ip: str, port: int) -> dict:
    """Versucht, einen Service-Banner abzugreifen."""
    info = {"product": "", "version": ""}
    try:
        # Für HTTP-Ports HTTP-Request senden
        if port in (80, 443, 8080, 8443, 8000, 8888):
            return info  # HTTP-Banner werden separat geholt
        sock.settimeout(3)
        # Einige Services senden sofort Banner
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        if banner:
            info["product"] = banner[:100]
    except Exception:
        pass
    return info


def _categorize_port(port: int) -> str:
    """Kategorisiert einen Port."""
    for category, ports in config.SCAN_PORTS.items():
        if port in ports:
            return category
    return "other"


def _guess_service(port: int) -> str:
    """Rät den Service basierend auf dem Port."""
    service_map = {
        21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http",
        110: "pop3", 139: "netbios", 143: "imap", 161: "snmp",
        162: "snmp-trap", 443: "https", 445: "smb", 465: "smtps",
        500: "isakmp", 587: "submission", 993: "imaps", 995: "pop3s",
        1194: "openvpn", 1433: "mssql", 1701: "l2tp", 3306: "mysql",
        3389: "rdp", 4500: "ike-nat", 5432: "postgresql",
        6379: "redis", 8080: "http-alt", 8443: "https-alt",
        8000: "http-alt", 8888: "http-alt", 27017: "mongodb",
    }
    return service_map.get(port, "unknown")


# ═════════════════════════════════════════════════════════════════════════════
#  Softwareaktualität (Banner-Grabbing & Fingerprinting)
# ═════════════════════════════════════════════════════════════════════════════

def detect_software(domain: str, hosts: list[dict], port_results: list[dict]) -> dict:
    """
    Erkennung laufender Software über HTTP-Header und HTML-Analyse.
    """
    print_progress("Attack Surface", "Software-Fingerprinting …")
    software = {
        "webservers": [],
        "cms": [],
        "js_libraries": [],
        "os_hints": [],
        "other_services": [],
        "favicon_tech_stack": [],
    }

    # ── HTTP-Header-Analyse ──
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        resp = http_get(url, verify_ssl=False)
        if resp is None:
            continue

        server = resp.headers.get("Server", "")
        if server:
            software["webservers"].append({"server": server, "url": url})

        powered_by = resp.headers.get("X-Powered-By", "")
        if powered_by:
            software["other_services"].append({"x_powered_by": powered_by, "url": url})

        # HTML-basierte Erkennung
        if resp.headers.get("Content-Type", "").startswith("text/html"):
            _detect_cms_and_libs(resp.text, url, software)
            
        # Favicon Hashing
        _check_favicon_hash(url, software)
        break  # Nur das erste erfolgreiche Schema

    # ── Nmap-Ergebnisse einbeziehen ──
    for pr in port_results:
        for port_info in pr.get("open_ports", []):
            if port_info.get("product"):
                software["other_services"].append({
                    "ip": pr["ip"],
                    "port": port_info["port"],
                    "product": port_info["product"],
                    "version": port_info["version"],
                    "cpe": port_info.get("cpe", ""),
                })

    log.info(f"Software-Erkennung abgeschlossen: {len(software['webservers'])} Webserver, {len(software['cms'])} CMS, {len(software['js_libraries'])} JS-Libs")
    return software


def _check_favicon_hash(url: str, software: dict):
    """Holt das Favicon, berechnet den MurmurHash3 und gleicht ihn ab."""
    try:
        import codecs
        import mmh3
        
        favicon_url = f"{url.rstrip('/')}/favicon.ico"
        resp = http_get(favicon_url, timeout=5, verify_ssl=False)
        if resp and resp.status_code == 200 and len(resp.content) > 0:
            favicon_b64 = codecs.encode(resp.content, "base64")
            hash_val = mmh3.hash(favicon_b64)
            
            # APT-Level Hash-Signatures
            signatures = {
                116323821: "Spring Boot",
                81586312: "Jenkins CI",
                -294389632: "Apache Tomcat",
                -296338574: "Atlassian Jira",
                516960814: "GitLab",
                116323820: "Spring Framework",
                1278323681: "Kubernetes Dashboard",
                -100860490: "React JS",
                -1886196568: "NextJS",
                1636283582: "JBoss"
            }
            
            detected = signatures.get(hash_val)
            if detected:
                software["favicon_tech_stack"].append({
                    "framework": detected,
                    "murmur_hash": hash_val,
                    "url": favicon_url
                })
                log.warning(f"  Favicon-Hash Match ({hash_val}): Verstecktes '{detected}' Interface erkannt!")
            else:
                software["favicon_tech_stack"].append({
                    "murmur_hash": hash_val,
                    "url": favicon_url,
                    "status": "Unknown Framework"
                })
    except ImportError:
        if "favicon_tech_stack" not in software:
            log.warning("mmh3 Bibliothek nicht installiert (pip install mmh3). Überspringe Favicon-Hashing.")
    except Exception as exc:
        pass


def _detect_cms_and_libs(html: str, url: str, software: dict):
    """Erkennt CMS und JavaScript-Bibliotheken aus HTML."""
    from bs4 import BeautifulSoup
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return

    # ── CMS Detection ──
    # WordPress
    if any(indicator in html.lower() for indicator in
           ["wp-content", "wp-includes", "wordpress", "/wp-json/"]):
        version = ""
        meta_gen = soup.find("meta", {"name": "generator"})
        if meta_gen and "wordpress" in meta_gen.get("content", "").lower():
            version = meta_gen["content"]
        software["cms"].append({"cms": "WordPress", "version": version, "url": url})


    # Joomla
    if any(indicator in html.lower() for indicator in
           ["/media/jui/", "/components/com_", "joomla"]):
        software["cms"].append({"cms": "Joomla", "version": "", "url": url})

    # Drupal
    if any(indicator in html.lower() for indicator in
           ["drupal.js", "drupal.min.js", "/sites/default/files/"]):
        software["cms"].append({"cms": "Drupal", "version": "", "url": url})

    # Typo3
    if any(indicator in html.lower() for indicator in
           ["typo3", "/typo3conf/", "typo3temp"]):
        software["cms"].append({"cms": "TYPO3", "version": "", "url": url})

    # ── JS Libraries ──
    scripts = soup.find_all("script", src=True)
    for script in scripts:
        src = script["src"]
        # jQuery
        match = re.search(r"jquery[.-](\d+\.\d+(?:\.\d+)?)", src, re.IGNORECASE)
        if match:
            software["js_libraries"].append({"library": "jQuery", "version": match.group(1), "src": src})
        # Bootstrap
        match = re.search(r"bootstrap[.-](\d+\.\d+(?:\.\d+)?)", src, re.IGNORECASE)
        if match:
            software["js_libraries"].append({"library": "Bootstrap", "version": match.group(1), "src": src})
        # Angular
        match = re.search(r"angular[.-](\d+\.\d+(?:\.\d+)?)", src, re.IGNORECASE)
        if match:
            software["js_libraries"].append({"library": "Angular", "version": match.group(1), "src": src})
        # React
        match = re.search(r"react[.-](\d+\.\d+(?:\.\d+)?)", src, re.IGNORECASE)
        if match:
            software["js_libraries"].append({"library": "React", "version": match.group(1), "src": src})
        # Vue
        match = re.search(r"vue[.-](\d+\.\d+(?:\.\d+)?)", src, re.IGNORECASE)
        if match:
            software["js_libraries"].append({"library": "Vue.js", "version": match.group(1), "src": src})


# ═════════════════════════════════════════════════════════════════════════════
#  Sicherheitslücken (CVE-Abgleich)
# ═════════════════════════════════════════════════════════════════════════════

def check_cves(software_info: dict) -> list[dict]:
    """
    Gleicht erkannte Software-Versionen gegen die NIST NVD API ab.
    """
    print_progress("Attack Surface", "CVE-Abgleich über NVD API …")
    cves = []

    # CPE-Strings aus Nmap-Ergebnissen
    for svc in software_info.get("other_services", []):
        cpe = svc.get("cpe", "")
        if cpe:
            found = _query_nvd(cpe)
            cves.extend(found)

    # Webserver-Versionen
    for ws in software_info.get("webservers", []):
        server = ws.get("server", "")
        cpe = _server_to_cpe(server)
        if cpe:
            found = _query_nvd(cpe)
            cves.extend(found)

    # CMS-Versionen
    for cms in software_info.get("cms", []):
        version = cms.get("version", "")
        cms_name = cms.get("cms", "").lower()
        if version:
            cpe = f"cpe:2.3:a:{cms_name}:{cms_name}:{version}:*:*:*:*:*:*:*"
            found = _query_nvd(cpe)
            cves.extend(found)

    if cves:
        log.warning(f"  {len(cves)} potentielle CVEs gefunden!")
    else:
        log.info("  Keine CVEs über NVD gefunden")

    return cves


def _query_nvd(cpe_string: str) -> list[dict]:
    """Fragt die NIST NVD API nach CVEs für einen CPE-String ab."""
    results = []
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cpeName": cpe_string, "resultsPerPage": 10}
        resp = http_get(f"{url}?cpeName={cpe_string}&resultsPerPage=10", timeout=15)
        if resp and resp.status_code == 200:
            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                description = ""
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                metrics = cve.get("metrics", {})
                cvss_score = ""
                severity = ""
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", "")
                        severity = cvss_data.get("baseSeverity", "")
                        break
                results.append({
                    "cve_id": cve_id,
                    "description": description[:200],
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "cpe": cpe_string,
                })
    except Exception as exc:
        log.debug(f"NVD-Abfrage fehlgeschlagen für {cpe_string}: {exc}")
    return results


def _server_to_cpe(server_banner: str) -> str:
    """Versucht aus einem Server-Banner einen CPE-String zu extrahieren."""
    server_lower = server_banner.lower()

    patterns = {
        r"apache[/ ]+(\d+\.\d+(?:\.\d+)?)": "cpe:2.3:a:apache:http_server:{ver}:*:*:*:*:*:*:*",
        r"nginx[/ ]+(\d+\.\d+(?:\.\d+)?)": "cpe:2.3:a:f5:nginx:{ver}:*:*:*:*:*:*:*",
        r"microsoft-iis[/ ]+(\d+\.\d+)": "cpe:2.3:a:microsoft:iis:{ver}:*:*:*:*:*:*:*",
        r"lighttpd[/ ]+(\d+\.\d+(?:\.\d+)?)": "cpe:2.3:a:lighttpd:lighttpd:{ver}:*:*:*:*:*:*:*",
        r"openresty[/ ]+(\d+\.\d+(?:\.\d+)?)": "cpe:2.3:a:openresty:openresty:{ver}:*:*:*:*:*:*:*",
    }

    for pattern, cpe_template in patterns.items():
        match = re.search(pattern, server_lower)
        if match:
            return cpe_template.replace("{ver}", match.group(1))
    return ""


# ═════════════════════════════════════════════════════════════════════════════
#  Interne Logins
# ═════════════════════════════════════════════════════════════════════════════

def find_login_portals(domain: str) -> list[dict]:
    """
    Sucht nach offenen Backend-Logins und VPN-Portalen.
    """
    print_progress("Attack Surface", "Suche nach Login-Portalen …")
    found = []

    for path in config.LOGIN_PATHS:
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}{path}"
            try:
                resp = http_get(url, timeout=config.HTTP_TIMEOUT, verify_ssl=False)
                if resp and resp.status_code == 200:
                    # Prüfe ob tatsächlich ein Login-Formular vorhanden ist
                    content = resp.text.lower()
                    is_login = any(indicator in content for indicator in [
                        "password", "passwort", "login", "sign in", "log in",
                        "anmelden", "authentif", "type=\"password\"",
                        "input type=\"password\"",
                    ])
                    if is_login:
                        found.append({
                            "url": url,
                            "status": resp.status_code,
                            "title": _extract_title(resp.text),
                            "type": _classify_login(path, resp.text),
                        })
                        log.warning(f"  Login-Portal gefunden: {url}")
                        break  # Nur ein Schema pro Pfad
            except Exception:
                continue

    log.info(f"Login-Suche abgeschlossen: {len(found)} Portale gefunden")
    return found


def _extract_title(html: str) -> str:
    """Extrahiert den <title>-Tag."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip()[:100] if match else ""


def _classify_login(path: str, html: str) -> str:
    """Klassifiziert den Login-Typ."""
    html_lower = html.lower()
    path_lower = path.lower()

    if "vpn" in path_lower or "vpn" in html_lower:
        return "VPN Portal"
    if "wp-" in path_lower or "wordpress" in html_lower:
        return "WordPress Admin"
    if "phpmyadmin" in path_lower or "phpmyadmin" in html_lower:
        return "phpMyAdmin"
    if "cpanel" in path_lower:
        return "cPanel"
    if "webmail" in path_lower:
        return "Webmail"
    if "sophos" in html_lower:
        return "Sophos VPN"
    if "fortinet" in html_lower or "fortigate" in html_lower:
        return "FortiGate VPN"
    return "Web Login"


# ═════════════════════════════════════════════════════════════════════════════
#  Bösartiger Netzwerkverkehr
# ═════════════════════════════════════════════════════════════════════════════

def check_malicious_traffic(hosts: list[dict]) -> dict:
    """
    Prüft alle IPs gegen Blacklists und Reputation-Dienste.
    """
    print_progress("Attack Surface", "Blacklist-/Reputation-Check …")
    results = {"blacklisted_ips": [], "reputation_checks": []}

    for host in hosts:
        ip = host["ip"]
        ip_result = {"ip": ip, "hostname": host.get("hostname", ""), "blacklists": [], "abuseipdb": None}

        # ── DNSBL-Check ──
        for bl in config.MAIL_DNSBLS:
            if check_dnsbl(ip, bl):
                ip_result["blacklists"].append(bl)
                log.warning(f"  {ip} auf Blacklist: {bl}")

        # ── AbuseIPDB ──
        api_key = config.API_KEYS.get("abuseipdb", "")
        if api_key:
            try:
                resp = http_get(
                    f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                    headers={"Key": api_key, "Accept": "application/json"},
                )
                if resp and resp.status_code == 200:
                    data = resp.json().get("data", {})
                    ip_result["abuseipdb"] = {
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "is_public": data.get("isPublic", True),
                        "isp": data.get("isp", ""),
                        "usage_type": data.get("usageType", ""),
                    }
            except Exception:
                pass

        # ── VirusTotal ──
        vt_key = config.API_KEYS.get("virustotal", "")
        if vt_key:
            try:
                resp = http_get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": vt_key},
                )
                if resp and resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    ip_result["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                    }
            except Exception:
                pass

        if ip_result["blacklists"]:
            results["blacklisted_ips"].append(ip_result)
        results["reputation_checks"].append(ip_result)

    return results

# ═════════════════════════════════════════════════════════════════════════════
#  Active Vulnerability Scanning (Nuclei) & Cloud Leaks
# ═════════════════════════════════════════════════════════════════════════════

def active_vulnerability_scan(domain: str, hosts: list[dict]) -> list[dict]:
    """Führt nuclei gegen entdeckte Web-Hosts aus."""
    print_progress("Attack Surface", "Aktives Vulnerability Scanning mit Nuclei …")
    results = []
    
    # Sammle alle relevanten URLs
    urls = set()
    for host in hosts:
        if "WEB" in host["roles"] or "VPN" in host["roles"] or "SRV" in host["roles"]:
            hostname = host["hostname"]
            urls.add(f"http://{hostname}")
            urls.add(f"https://{hostname}")
            
    if not urls:
        return results
        
    try:
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("\n".join(list(urls)))
            target_file = tf.name
            
        with tempfile.NamedTemporaryFile("r", delete=False) as json_out:
            json_file = json_out.name
            
        # nuclei ausführen (-severity low,medium,high,critical)
        cmd = [
            "nuclei", "-l", target_file, "-j",
            "-o", json_file,
            "-severity", "low,medium,high,critical",
            "-silent"
        ]
        log.info(f"Führe Nuclei aus für {len(urls)} URLs...")
        subprocess.run(cmd, timeout=300)
        
        with open(json_file, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        finding = json.loads(line)
                        results.append({
                            "template_id": finding.get("template-id", ""),
                            "name": finding.get("info", {}).get("name", ""),
                            "severity": finding.get("info", {}).get("severity", ""),
                            "host": finding.get("host", ""),
                            "type": finding.get("type", ""),
                            "matched_at": finding.get("matched-at", ""),
                            "description": finding.get("info", {}).get("description", ""),
                            "curl_command": finding.get("curl-command", "")
                        })
                    except json.JSONDecodeError:
                        continue
                        
        os.remove(target_file)
        os.remove(json_file)
    except FileNotFoundError:
        log.warning("nuclei nicht gefunden. Bitte via 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' installieren.")
    except subprocess.TimeoutExpired:
        log.warning("nuclei Scan wegen Überzeit (300s) abgebrochen.")
    except Exception as exc:
        log.warning(f"Fehler bei nuclei: {exc}")
        
    if results:
        log.warning(f"  {len(results)} Findings durch Nuclei entdeckt!")
    else:
        log.info("  Keine signifikanten Lücken durch Nuclei gefunden.")
    return results


def check_cloud_leaks(domain: str, subdomains: list[str]) -> list[dict]:
    """Prüft typische Cloud-Speicher-Namenstrukturen auf Existenz und offenen Zugriff."""
    print_progress("Attack Surface", "Cloud Leak Check (S3 / Azure) …")
    found_buckets = []
    
    # Base names ableiten
    basenames = [domain.replace(".", ""), domain.replace(".", "-"), domain.split(".")[0]]
    for sub in subdomains:
        if sub != domain and sub.endswith(f".{domain}"):
            basenames.append(sub.split(".")[0])
            
    basenames = list(set([b for b in basenames if b]))
    environments = ["", "-dev", "-prod", "-staging", "-test", "-backup", "-assets", "-public"]
    
    for base in basenames:
        for env in environments:
            bucket_name = f"{base}{env}".lower()
            
            # AWS S3 check
            s3_url = f"https://{bucket_name}.s3.amazonaws.com"
            try:
                resp = http_get(s3_url, timeout=5, verify_ssl=False)
                if resp:
                    if resp.status_code == 200 and "ListBucketResult" in resp.text:
                        found_buckets.append({
                            "provider": "AWS S3",
                            "url": s3_url,
                            "name": bucket_name,
                            "access": "Publicly Listable (CRITICAL)",
                            "status_code": 200
                        })
                    elif resp.status_code in (401, 403):
                        found_buckets.append({
                            "provider": "AWS S3",
                            "url": s3_url,
                            "name": bucket_name,
                            "access": "Exists (Access Denied)",
                            "status_code": resp.status_code
                        })
            except Exception:
                pass
                
    if found_buckets:
        log.info(f"  {len(found_buckets)} Cloud-Buckets identifiziert.")
    return found_buckets


# ═════════════════════════════════════════════════════════════════════════════
#  Hauptfunktion Modul 1
# ═════════════════════════════════════════════════════════════════════════════

def run(domain: str, on_progress=None) -> dict:
    """Führt alle Scans des Moduls 'Angriffsoberfläche' aus."""
    result = {}

    # 1. Host-Discovery
    host_discovery = discover_hosts(domain)
    result["host_discovery"] = host_discovery
    if on_progress:
        on_progress(result.copy(), f"host discovery: {len(host_discovery.get('hosts', []))} host(s)")

    # 2. Offene Zugänge
    port_results = []

    def _port_progress(partial_ports, done, total, _host_result):
        result["open_ports"] = partial_ports
        if on_progress:
            on_progress(result.copy(), f"port scan: {done}/{total} host(s)")

    port_results = scan_open_ports(host_discovery["hosts"], on_host_done=_port_progress)
    result["open_ports"] = port_results
    if on_progress:
        on_progress(result.copy(), f"port scan complete: {len(port_results)} host result(s)")

    # 3. Software-Erkennung
    software = detect_software(domain, host_discovery["hosts"], port_results)
    result["software"] = software
    if on_progress:
        on_progress(result.copy(), f"software fingerprinting: {len(software)} finding(s)")

    # 4. CVE-Abgleich
    result["cves"] = check_cves(software)
    if on_progress:
        on_progress(result.copy(), f"cve check: {len(result['cves'])} finding(s)")

    # 5. Login-Portale
    result["login_portals"] = find_login_portals(domain)
    if on_progress:
        on_progress(result.copy(), f"login portal check: {len(result['login_portals'])} portal(s)")

    # 6. Malicious Traffic
    result["malicious_traffic"] = check_malicious_traffic(host_discovery["hosts"])
    if on_progress:
        on_progress(result.copy(), "reputation check complete")

    # 7. Active Vulnerability Scanning (Nuclei)
    result["active_vulnerabilities"] = active_vulnerability_scan(domain, host_discovery["hosts"])
    if on_progress:
        on_progress(result.copy(), f"active vulnerability scan: {len(result['active_vulnerabilities'])} finding(s)")

    # 8. Cloud Leaks
    result["cloud_leaks"] = check_cloud_leaks(domain, host_discovery["subdomains"])
    if on_progress:
        on_progress(result.copy(), f"cloud leak check: {len(result['cloud_leaks'])} finding(s)")

    return result
