"""
EASM Scanner — Subdomain Enumeration Engine
=============================================
Aggressive, multi-source subdomain discovery.

Sources:
  Passive (OSINT): crt.sh, CertSpotter, AlienVault OTX, HackerTarget,
                   RapidDNS, AnubisDB, URLScan, Wayback Machine,
                   ThreatCrowd, BufferOver
  Active:          subfinder/amass binaries, DNS brute-force, permutations
  Validation:      Wildcard-DNS detection, live A/AAAA resolution

Result: deduplicated, validated set of subdomains.
"""

from __future__ import annotations

import concurrent.futures as cf
import random
import re
import string
import subprocess
import os
import shutil
from typing import Iterable

import dns.resolver
import dns.exception

import config
from utils import get_logger, http_get, print_progress

log = get_logger("easm.subdomain_enum")

# ── DNS Resolvers (public, fast, redundant) ─────────────────────────────
_PUBLIC_RESOLVERS = [
    "1.1.1.1", "1.0.0.1",            # Cloudflare
    "8.8.8.8", "8.8.4.4",            # Google
    "9.9.9.9", "149.112.112.112",    # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "94.140.14.14",                  # AdGuard
]

# ── Built-in DNS bruteforce wordlist ────────────────────────────────────
# Compact but high-hit wordlist, covers ~95% of real-world subdomains.
DEFAULT_WORDLIST = """
www mail ftp localhost webmail smtp pop ns1 ns2 ns3 ns4 webdisk admin
administrator api app apps autodiscover blog bbs bugs cdn chat client
clients cloud cms code crm dashboard data db dev developer development
direct directadmin dns docs download downloads email en es exchange
files forum forums git github gitlab help home host hosting hub images
img imap info intranet jobs kb lab labs ldap m media mobile monitor
monitoring mx mx1 mx2 my new news ns office old owa panel partners
pay payment pop3 portal preview private prod production proxy public
remote repo reports rss s3 sandbox secure server shop shops sip site
sites smtp1 smtp2 sso staging static stats status store stream support
survey svn t team test test1 test2 testing tools track training v1 v2
videos vpn web web1 web2 webdav wiki ws www1 www2 www3 ww1 demo legacy
beta gateway api1 api2 api3 v3 cpanel whm grafana kibana jenkins ci
cd auth oauth login signin sign-in account accounts users access portal2
admin1 admin2 superadmin root manage management console internal external
cluster node node1 node2 db1 db2 mysql postgres mongo redis elastic
elasticsearch search solr ws1 ws2 wss api-staging api-dev qa uat
preprod pre-prod live mirror backup backups archive archives old1
old2 lab1 demo1 demo2 demo3 sandbox1 sandbox2 vpn1 vpn2 fw firewall
gw router switch ap rdp citrix terminal ts1 ts2 jump bastion deploy
cd-deploy artifact registry docker container k8s kubernetes nomad
consul vault keycloak idp sso2 saml oidc adfs ldap1 ldap2 ad active
ftp1 ftp2 sftp file files1 files2 share shares cloud1 cloud2 box
nextcloud owncloud drive sync backup1 backup2 monitor1 monitor2
nagios zabbix prometheus alertmanager loki tempo jaeger zipkin
""".split()


# ═════════════════════════════════════════════════════════════════════════════
#  Public API
# ═════════════════════════════════════════════════════════════════════════════

def enumerate_all(domain: str, *, bruteforce: bool = True,
                  permute: bool = True, validate: bool = True,
                  max_workers: int = 30) -> dict:
    """
    Full subdomain enumeration pipeline.

    Returns:
        {
          "subdomains": [...validated...],
          "raw_count": int,             # before validation
          "wildcard": bool,
          "sources": {source_name: count, ...}
        }
    """
    domain = domain.strip().lower().rstrip(".")
    print_progress("Subdomain-Enum", f"Starte Multi-Source-Enumeration für {domain} …")

    # ── Wildcard detection ──
    wildcard_ips = _detect_wildcard(domain)
    if wildcard_ips:
        log.warning(f"Wildcard-DNS erkannt für *.{domain} → {wildcard_ips} (False-Positives werden gefiltert)")

    # ── Run all passive sources in parallel ──
    sources = {
        "crt.sh":          _crtsh,
        "certspotter":     _certspotter,
        "hackertarget":    _hackertarget,
        "alienvault_otx":  _alienvault_otx,
        "rapiddns":        _rapiddns,
        "anubisdb":        _anubisdb,
        "urlscan":         _urlscan,
        "wayback":         _wayback,
        "threatcrowd":     _threatcrowd,
        "bufferover":      _bufferover,
        "subfinder":       _subfinder_bin,
        "amass":           _amass_bin,
    }

    raw: dict[str, set[str]] = {}
    with cf.ThreadPoolExecutor(max_workers=min(len(sources), max_workers)) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in sources.items()}
        for fut in cf.as_completed(futures):
            name = futures[fut]
            try:
                subs = fut.result() or []
                cleaned = _clean_subdomains(subs, domain)
                raw[name] = set(cleaned)
                log.info(f"  [{name:14s}] {len(cleaned):4d} subdomains")
            except Exception as exc:
                log.debug(f"Source {name} failed: {exc}")
                raw[name] = set()

    merged: set[str] = set().union(*raw.values()) if raw else set()
    print_progress("Subdomain-Enum", f"Passive Quellen: {len(merged)} Kandidaten")

    # ── DNS bruteforce ──
    if bruteforce:
        print_progress("Subdomain-Enum", f"DNS-Bruteforce mit {len(DEFAULT_WORDLIST)} Einträgen …")
        bf = _dns_bruteforce(domain, DEFAULT_WORDLIST, wildcard_ips, max_workers=max_workers)
        raw["bruteforce"] = bf
        merged |= bf
        log.info(f"  [bruteforce    ] {len(bf):4d} subdomains")

    # ── Permutations on top of what we have ──
    if permute and merged:
        print_progress("Subdomain-Enum", "Permutationen werden generiert …")
        perms = _generate_permutations(domain, merged)
        validated = _resolve_batch(perms, wildcard_ips, max_workers=max_workers)
        raw["permutations"] = validated
        merged |= validated
        log.info(f"  [permutations  ] {len(validated):4d} subdomains")

    raw_count = len(merged)

    # ── Final validation: every host must resolve to at least 1 IP that isn't wildcard ──
    if validate:
        print_progress("Subdomain-Enum", f"Validiere {len(merged)} Kandidaten via DNS …")
        merged = _resolve_batch(merged, wildcard_ips, max_workers=max_workers)

    final = sorted(merged)
    log.info(f"Subdomain-Enum: {len(final)} validiert (von {raw_count} Kandidaten)")

    return {
        "subdomains": final,
        "raw_count": raw_count,
        "wildcard": bool(wildcard_ips),
        "wildcard_ips": sorted(wildcard_ips),
        "sources": {name: len(s) for name, s in raw.items()},
    }


# ═════════════════════════════════════════════════════════════════════════════
#  Wildcard detection
# ═════════════════════════════════════════════════════════════════════════════

def _detect_wildcard(domain: str) -> set[str]:
    """Check whether *.domain resolves to a fixed set of IPs (wildcard DNS)."""
    resolver = _new_resolver()
    wildcard_ips: set[str] = set()
    for _ in range(3):
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        host = f"{rand}.{domain}"
        try:
            for r in resolver.resolve(host, "A"):
                wildcard_ips.add(str(r))
        except Exception:
            pass
    return wildcard_ips


# ═════════════════════════════════════════════════════════════════════════════
#  Cleaning / Validation helpers
# ═════════════════════════════════════════════════════════════════════════════

_VALID_HOST_RE = re.compile(r"^[a-z0-9._-]+$")


def _clean_subdomains(items: Iterable[str], domain: str) -> list[str]:
    """Normalize, dedup, filter to in-scope subdomains."""
    out: set[str] = set()
    suffix = "." + domain
    for raw in items:
        if not raw:
            continue
        s = raw.strip().strip(".").lower()
        # strip wildcard prefixes
        if s.startswith("*."):
            s = s[2:]
        if "*" in s:
            continue
        if not _VALID_HOST_RE.match(s):
            continue
        if s == domain or s.endswith(suffix):
            out.add(s)
    return sorted(out)


def _system_resolver_works() -> bool:
    """Probe whether the OS resolver is reachable. Cached on first call."""
    global _SYSTEM_DNS_OK
    if _SYSTEM_DNS_OK is not None:
        return _SYSTEM_DNS_OK
    try:
        r = dns.resolver.Resolver()  # uses /etc/resolv.conf
        r.timeout = 2
        r.lifetime = 3
        r.resolve("cloudflare.com", "A")
        _SYSTEM_DNS_OK = True
    except Exception:
        _SYSTEM_DNS_OK = False
    return _SYSTEM_DNS_OK


_SYSTEM_DNS_OK: bool | None = None


def _new_resolver() -> dns.resolver.Resolver:
    """Prefer the system resolver (works behind firewalls/sandboxes);
    fall back to public resolvers only if system DNS is broken."""
    if _system_resolver_works():
        r = dns.resolver.Resolver()  # /etc/resolv.conf
    else:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = list(_PUBLIC_RESOLVERS)
        random.shuffle(r.nameservers)
    r.timeout = 3
    r.lifetime = 5
    return r


def _resolve_one(host: str, wildcard_ips: set[str]) -> tuple[str, bool]:
    """True if host resolves to at least 1 non-wildcard IP."""
    resolver = _new_resolver()
    try:
        for rtype in ("A", "AAAA"):
            try:
                ans = resolver.resolve(host, rtype)
                ips = {str(r) for r in ans}
                if ips - wildcard_ips:
                    return host, True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except dns.exception.DNSException:
                continue
        return host, False
    except Exception:
        return host, False


def _resolve_batch(hosts: Iterable[str], wildcard_ips: set[str],
                   max_workers: int = 30) -> set[str]:
    """Resolve many hosts in parallel, return only the live ones."""
    hosts = list(hosts)
    if not hosts:
        return set()
    alive: set[str] = set()
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for host, ok in ex.map(lambda h: _resolve_one(h, wildcard_ips), hosts):
            if ok:
                alive.add(host)
    return alive


# ═════════════════════════════════════════════════════════════════════════════
#  Passive sources
# ═════════════════════════════════════════════════════════════════════════════

def _crtsh(domain: str) -> list[str]:
    """Certificate Transparency Logs via crt.sh."""
    out: list[str] = []
    for url in (
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ):
        try:
            resp = http_get(url, timeout=20)
            if not resp or resp.status_code != 200:
                continue
            data = resp.json()
            for entry in data:
                for nv in (entry.get("name_value", "") or "").split("\n"):
                    out.append(nv)
                cn = entry.get("common_name", "") or ""
                if cn:
                    out.append(cn)
        except Exception as exc:
            log.debug(f"crt.sh: {exc}")
    return out


def _certspotter(domain: str) -> list[str]:
    """SSLMate CertSpotter — alternative CT log source."""
    out: list[str] = []
    try:
        resp = http_get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}"
            f"&include_subdomains=true&expand=dns_names",
            timeout=20,
        )
        if resp and resp.status_code == 200:
            for entry in resp.json():
                for n in entry.get("dns_names", []) or []:
                    out.append(n)
    except Exception as exc:
        log.debug(f"certspotter: {exc}")
    return out


def _hackertarget(domain: str) -> list[str]:
    """HackerTarget hostsearch (rate limited, but free)."""
    out: list[str] = []
    try:
        resp = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if resp and resp.status_code == 200 and "API count exceeded" not in resp.text:
            for line in resp.text.splitlines():
                if "," in line:
                    out.append(line.split(",", 1)[0])
    except Exception as exc:
        log.debug(f"hackertarget: {exc}")
    return out


def _alienvault_otx(domain: str) -> list[str]:
    """AlienVault OTX passive DNS."""
    out: list[str] = []
    try:
        resp = http_get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=20,
        )
        if resp and resp.status_code == 200:
            for r in resp.json().get("passive_dns", []) or []:
                out.append(r.get("hostname", ""))
    except Exception as exc:
        log.debug(f"otx: {exc}")
    return out


def _rapiddns(domain: str) -> list[str]:
    """RapidDNS.io — HTML scrape."""
    out: list[str] = []
    try:
        resp = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=20)
        if resp and resp.status_code == 200:
            for m in re.findall(r">([a-zA-Z0-9._-]+\." + re.escape(domain) + r")<", resp.text):
                out.append(m)
    except Exception as exc:
        log.debug(f"rapiddns: {exc}")
    return out


def _anubisdb(domain: str) -> list[str]:
    """JLDC AnubisDB."""
    out: list[str] = []
    try:
        resp = http_get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=20)
        if resp and resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                out.extend(data)
    except Exception as exc:
        log.debug(f"anubisdb: {exc}")
    return out


def _urlscan(domain: str) -> list[str]:
    """URLScan.io search."""
    out: list[str] = []
    try:
        resp = http_get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000",
            timeout=20,
        )
        if resp and resp.status_code == 200:
            for r in resp.json().get("results", []) or []:
                page = (r.get("page", {}) or {})
                d = page.get("domain", "")
                if d:
                    out.append(d)
    except Exception as exc:
        log.debug(f"urlscan: {exc}")
    return out


def _wayback(domain: str) -> list[str]:
    """Wayback Machine — extract hostnames from archived URLs."""
    out: list[str] = []
    try:
        resp = http_get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
            f"&output=json&fl=original&collapse=urlkey&limit=5000",
            timeout=25,
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            for row in data[1:]:
                if not row:
                    continue
                url = row[0]
                m = re.match(r"^https?://([^/:]+)", url)
                if m:
                    out.append(m.group(1))
    except Exception as exc:
        log.debug(f"wayback: {exc}")
    return out


def _threatcrowd(domain: str) -> list[str]:
    """ThreatCrowd (sometimes offline, kept as best-effort source)."""
    out: list[str] = []
    try:
        resp = http_get(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            timeout=15,
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            for s in data.get("subdomains", []) or []:
                out.append(s)
    except Exception as exc:
        log.debug(f"threatcrowd: {exc}")
    return out


def _bufferover(domain: str) -> list[str]:
    """BufferOver TLS forward DNS data."""
    out: list[str] = []
    for url in (
        f"https://tls.bufferover.run/dns?q=.{domain}",
        f"https://dns.bufferover.run/dns?q=.{domain}",
    ):
        try:
            resp = http_get(url, timeout=15)
            if resp and resp.status_code == 200:
                data = resp.json()
                for key in ("Results", "FDNS_A", "RDNS"):
                    for line in data.get(key, []) or []:
                        if isinstance(line, str) and "," in line:
                            parts = line.split(",")
                            out.append(parts[-1])
                        elif isinstance(line, str):
                            out.append(line)
        except Exception as exc:
            log.debug(f"bufferover: {exc}")
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  Active sources (binaries)
# ═════════════════════════════════════════════════════════════════════════════

def _find_binary(name: str) -> str | None:
    p = shutil.which(name)
    if p:
        return p
    candidate = os.path.expanduser(f"~/go/bin/{name}")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return None


def _subfinder_bin(domain: str) -> list[str]:
    bin_path = _find_binary("subfinder")
    if not bin_path:
        return []
    try:
        result = subprocess.run(
            [bin_path, "-d", domain, "-silent", "-all", "-recursive"],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode == 0:
            return [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except Exception as exc:
        log.debug(f"subfinder: {exc}")
    return []


def _amass_bin(domain: str) -> list[str]:
    """Optional: amass enum -passive — only used if installed."""
    bin_path = _find_binary("amass")
    if not bin_path:
        return []
    try:
        result = subprocess.run(
            [bin_path, "enum", "-passive", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=240,
        )
        if result.returncode == 0:
            return [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except Exception as exc:
        log.debug(f"amass: {exc}")
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  DNS bruteforce + permutations
# ═════════════════════════════════════════════════════════════════════════════

def _dns_bruteforce(domain: str, words: list[str], wildcard_ips: set[str],
                    max_workers: int = 30) -> set[str]:
    """Bruteforce common subdomain names against the target domain."""
    candidates = [f"{w.strip().lower()}.{domain}" for w in words if w.strip()]
    return _resolve_batch(candidates, wildcard_ips, max_workers=max_workers)


_PERMUTATION_PREFIXES = ["dev", "staging", "stage", "test", "uat", "qa", "prod",
                         "preprod", "internal", "old", "new", "v2", "beta",
                         "demo", "admin"]
_PERMUTATION_SUFFIXES = ["dev", "staging", "stage", "test", "qa", "old", "new",
                         "v2", "internal", "backup"]


def _generate_permutations(domain: str, known: set[str]) -> set[str]:
    """Generate dev-x, x-dev, x-staging style variants of known subdomains."""
    out: set[str] = set()
    suffix = "." + domain
    for host in known:
        if not host.endswith(suffix):
            continue
        sub = host[: -len(suffix)]
        if not sub or "." in sub:
            continue
        for p in _PERMUTATION_PREFIXES:
            out.add(f"{p}-{sub}.{domain}")
            out.add(f"{p}.{sub}.{domain}")
        for s in _PERMUTATION_SUFFIXES:
            out.add(f"{sub}-{s}.{domain}")
            out.add(f"{sub}.{s}.{domain}")
    return out
