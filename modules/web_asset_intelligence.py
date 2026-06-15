"""
EASM Scanner - Module 14: Web Asset Intelligence
================================================
Fast, bounded web exposure mapping:
  - live web asset inventory across discovered subdomains
  - admin/dev panel hints
  - API documentation and GraphQL endpoint hints
  - artifact exposure checks via HEAD / tiny range requests
  - CORS and cookie security signals

The module is intentionally non-destructive and time-boxed. It does not crawl
deeply, brute-force credentials, download backup files, or run GraphQL
introspection.
"""

from __future__ import annotations

import concurrent.futures as cf
import re
from urllib.parse import urljoin, urlparse

import config
from utils import get_logger, http_get, http_head, print_progress

log = get_logger("easm.web_asset_intel")


HIGH_VALUE_HOST_KEYWORDS = (
    "admin", "api", "app", "auth", "dev", "grafana", "idp", "internal",
    "jenkins", "kibana", "keycloak", "login", "manage", "monitor",
    "portal", "sso", "stage", "staging", "test", "vpn",
)

API_PATHS = (
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui/",
    "/swagger/index.html",
    "/redoc",
    "/graphql",
    "/graphiql",
    "/.well-known/openid-configuration",
)

PANEL_PATHS = (
    "/admin",
    "/login",
    "/wp-login.php",
    "/wp-admin/",
    "/grafana/login",
    "/kibana",
    "/jenkins/login",
    "/sonarqube",
    "/actuator",
    "/actuator/health",
    "/metrics",
    "/prometheus",
    "/phpmyadmin/",
    "/adminer.php",
    "/portainer/",
)

ARTIFACT_PATHS = (
    "/.env",
    "/.git/config",
    "/.DS_Store",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/dump.sql",
    "/database.sql",
    "/db.sql",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/robots.txt",
    "/sitemap.xml",
)

INTERESTING_STATUS = {200, 206, 301, 302, 307, 308, 401, 403}


def _extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:120]


def _get_set_cookies(resp) -> list[str]:
    try:
        return list(resp.headers.get_list("set-cookie"))
    except Exception:
        value = resp.headers.get("set-cookie", "")
        return [value] if value else []


def _cookie_issues(resp) -> list[dict]:
    issues: list[dict] = []
    for raw in _get_set_cookies(resp):
        if not raw:
            continue
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        sensitive = any(k in name.lower() for k in ("sess", "auth", "token", "jwt", "sid"))
        severity = "MEDIUM" if sensitive else "LOW"

        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if not missing:
            continue
        issues.append({
            "cookie": name,
            "missing": missing,
            "severity": severity,
            "evidence": "; ".join(missing),
        })
    return issues


def _detect_tech(resp, body: str) -> list[str]:
    tech: set[str] = set()
    headers = {k.lower(): v for k, v in resp.headers.items()}
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server:
        tech.add(f"Server: {server[:80]}")
    if powered:
        tech.add(f"X-Powered-By: {powered[:80]}")

    low = body.lower()
    markers = {
        "WordPress": ("wp-content", "wp-includes", "wp-json"),
        "TYPO3": ("typo3conf", "typo3temp", "typo3"),
        "Drupal": ("drupal.js", "/sites/default/"),
        "Next.js": ("_next/static", "__next_data__"),
        "React": ("react-dom", "react.production.min"),
        "Vue": ("vue.js", "__vue__"),
        "Angular": ("ng-version", "angular.js"),
        "Grafana": ("grafana", "login to grafana"),
        "Keycloak": ("keycloak", "kc-login"),
        "Swagger UI": ("swagger-ui", "swagger-ui-bundle"),
    }
    for name, needles in markers.items():
        if any(n in low for n in needles):
            tech.add(name)
    return sorted(tech)


def _prioritize_hosts(domain: str, subdomains: list[str] | None) -> list[str]:
    candidates = {domain.strip().lower().rstrip("."), f"www.{domain.strip().lower().rstrip('.')}"}
    for sub in subdomains or []:
        sub = sub.strip().lower().rstrip(".")
        if sub and (sub == domain or sub.endswith("." + domain)):
            candidates.add(sub)

    def score(host: str) -> tuple[int, str]:
        if host == domain:
            return (0, host)
        if host == f"www.{domain}":
            return (1, host)
        if any(k in host for k in HIGH_VALUE_HOST_KEYWORDS):
            return (2, host)
        return (3, host)

    return [h for h in sorted(candidates, key=score)[: config.WEB_INTEL_MAX_HOSTS]]


def _probe_host(host: str) -> dict | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        resp = http_get(url, timeout=config.WEB_INTEL_TIMEOUT, verify_ssl=False)
        if not resp or resp.status_code >= 500:
            continue

        body = resp.text or ""
        final_url = str(resp.url)
        parsed_final = urlparse(final_url)
        return {
            "host": host,
            "url": url,
            "final_url": final_url,
            "status": resp.status_code,
            "title": _extract_title(body),
            "content_type": resp.headers.get("content-type", ""),
            "server": resp.headers.get("server", ""),
            "redirected": parsed_final.netloc.lower() != host.lower() or final_url.rstrip("/") != url.rstrip("/"),
            "technologies": _detect_tech(resp, body),
            "cookie_issues": _cookie_issues(resp),
        }
    return None


def _rank_assets_for_paths(assets: list[dict]) -> list[dict]:
    def score(asset: dict) -> tuple[int, str]:
        host = asset.get("host", "")
        if any(k in host for k in HIGH_VALUE_HOST_KEYWORDS):
            return (0, host)
        if host.startswith("www."):
            return (1, host)
        if host.count(".") <= 1:
            return (1, host)
        return (2, host)

    return sorted(assets, key=score)[: config.WEB_INTEL_MAX_PATH_ASSETS]


def _tiny_get(url: str):
    return http_get(
        url,
        timeout=config.WEB_INTEL_TIMEOUT,
        verify_ssl=False,
        headers={"Range": "bytes=0-4095"},
    )


def _check_api_path(base_url: str, path: str) -> dict | None:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    resp = _tiny_get(url)
    if not resp or resp.status_code not in INTERESTING_STATUS:
        return None
    body = (resp.text or "")[:4096]
    low = body.lower()
    ctype = resp.headers.get("content-type", "")
    evidence = ""
    severity = "INFO"

    if "openapi" in low or '"swagger"' in low or "swagger-ui" in low:
        evidence = "OpenAPI/Swagger indicator"
        severity = "MEDIUM"
    elif "graphql" in low or path in ("/graphql", "/graphiql"):
        evidence = "GraphQL endpoint indicator"
        severity = "MEDIUM" if resp.status_code in (200, 400, 405) else "INFO"
    elif "openid-configuration" in path or ("issuer" in low and "authorization_endpoint" in low):
        evidence = "OIDC metadata"
        severity = "INFO"
    elif resp.status_code in (401, 403):
        evidence = "protected endpoint exists"
    elif resp.status_code == 200 and ("json" in ctype or "api" in path):
        evidence = "API-looking endpoint responded"
        severity = "LOW"
    else:
        return None

    return {
        "url": url,
        "path": path,
        "status": resp.status_code,
        "severity": severity,
        "evidence": evidence,
        "title": _extract_title(body),
        "content_type": ctype,
    }


def _check_panel_path(base_url: str, path: str) -> dict | None:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    resp = _tiny_get(url)
    if not resp or resp.status_code not in INTERESTING_STATUS:
        return None

    body = (resp.text or "")[:4096]
    low = body.lower()
    title = _extract_title(body)
    panel_markers = (
        "password", "sign in", "login", "grafana", "kibana", "jenkins",
        "sonarqube", "phpmyadmin", "adminer", "actuator", "prometheus",
        "portainer",
    )
    if resp.status_code == 200 and not any(m in low for m in panel_markers):
        return None

    severity = "MEDIUM" if path not in ("/login", "/admin", "/wp-login.php", "/wp-admin/") else "INFO"
    if any(k in path for k in ("actuator", "metrics", "prometheus", "jenkins", "phpmyadmin", "adminer")):
        severity = "HIGH" if resp.status_code == 200 else "MEDIUM"

    return {
        "url": url,
        "path": path,
        "status": resp.status_code,
        "severity": severity,
        "title": title,
        "evidence": "panel/login marker or protected admin path",
    }


def _check_artifact_path(base_url: str, path: str) -> dict | None:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    resp = http_head(url, timeout=config.WEB_INTEL_TIMEOUT, verify_ssl=False)
    if not resp or resp.status_code == 405:
        resp = _tiny_get(url)
    if not resp or resp.status_code not in INTERESTING_STATUS:
        return None

    sensitive = path not in ("/robots.txt", "/sitemap.xml")
    if not sensitive and resp.status_code not in (200, 206):
        return None

    severity = "INFO"
    if sensitive:
        severity = "CRITICAL" if resp.status_code in (200, 206) else "MEDIUM"

    return {
        "url": url,
        "path": path,
        "status": resp.status_code,
        "severity": severity,
        "content_type": resp.headers.get("content-type", ""),
        "content_length": resp.headers.get("content-length", ""),
        "evidence": "metadata only; file body not downloaded",
    }


def _check_cors(asset: dict) -> dict | None:
    origin = "https://example-attacker.invalid"
    resp = http_get(
        asset["url"],
        timeout=config.WEB_INTEL_TIMEOUT,
        verify_ssl=False,
        headers={"Origin": origin},
    )
    if not resp:
        return None
    acao = resp.headers.get("access-control-allow-origin", "")
    accred = resp.headers.get("access-control-allow-credentials", "")
    if not acao:
        return None
    if acao == "*" or acao == origin:
        severity = "HIGH" if accred.lower() == "true" else "MEDIUM"
        return {
            "url": asset["url"],
            "severity": severity,
            "allow_origin": acao,
            "allow_credentials": accred,
        }
    return None


def _run_path_checks(assets: list[dict]) -> dict:
    selected = _rank_assets_for_paths(assets)
    findings = {"api_docs": [], "admin_panels": [], "exposed_artifacts": [], "cors_issues": []}
    tasks = []
    with cf.ThreadPoolExecutor(max_workers=config.WEB_INTEL_MAX_WORKERS) as ex:
        for asset in selected:
            base_url = asset["url"]
            tasks.extend(ex.submit(_check_api_path, base_url, path) for path in API_PATHS)
            tasks.extend(ex.submit(_check_panel_path, base_url, path) for path in PANEL_PATHS)
            tasks.extend(ex.submit(_check_artifact_path, base_url, path) for path in ARTIFACT_PATHS)
            tasks.append(ex.submit(_check_cors, asset))

        for fut in cf.as_completed(tasks):
            try:
                item = fut.result()
            except Exception:
                continue
            if not item:
                continue
            path = item.get("path", "")
            if path in API_PATHS:
                findings["api_docs"].append(item)
            elif path in PANEL_PATHS:
                findings["admin_panels"].append(item)
            elif path in ARTIFACT_PATHS:
                findings["exposed_artifacts"].append(item)
            else:
                findings["cors_issues"].append(item)
    return findings


def run(domain: str, subdomains: list[str] | None = None) -> dict:
    """Run fast web intelligence checks for a bounded host set."""
    print_progress("Web Asset Intel", "Fast web asset mapping and exposure checks ...")

    hosts = _prioritize_hosts(domain, subdomains)
    assets: list[dict] = []
    with cf.ThreadPoolExecutor(max_workers=config.WEB_INTEL_MAX_WORKERS) as ex:
        for asset in ex.map(_probe_host, hosts):
            if asset:
                assets.append(asset)

    log.info(f"Web Asset Intel: {len(assets)} live web assets from {len(hosts)} candidate hosts")
    path_findings = _run_path_checks(assets) if assets else {
        "api_docs": [], "admin_panels": [], "exposed_artifacts": [], "cors_issues": []
    }

    cookie_issues = []
    for asset in assets:
        for issue in asset.get("cookie_issues", []) or []:
            cookie_issues.append({
                "url": asset.get("url"),
                "host": asset.get("host"),
                **issue,
            })

    return {
        "limits": {
            "max_hosts": config.WEB_INTEL_MAX_HOSTS,
            "max_path_assets": config.WEB_INTEL_MAX_PATH_ASSETS,
            "timeout": config.WEB_INTEL_TIMEOUT,
        },
        "candidate_hosts": len(hosts),
        "live_assets": sorted(assets, key=lambda a: a.get("host", "")),
        "api_docs": sorted(path_findings["api_docs"], key=lambda x: x.get("url", "")),
        "admin_panels": sorted(path_findings["admin_panels"], key=lambda x: x.get("url", "")),
        "exposed_artifacts": sorted(path_findings["exposed_artifacts"], key=lambda x: x.get("url", "")),
        "cors_issues": sorted(path_findings["cors_issues"], key=lambda x: x.get("url", "")),
        "cookie_issues": sorted(cookie_issues, key=lambda x: (x.get("url", ""), x.get("cookie", ""))),
    }
