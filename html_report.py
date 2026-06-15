"""
EASM Scanner — HTML Report Generator
======================================
Generates customer-facing HTML reports with:
  - Executive summary + risk score
  - Severity-categorized findings (CRITICAL/HIGH/MEDIUM/LOW/INFO)
  - Per-module detailed sections
  - Self-contained (inline CSS, no external assets)
  - Print-friendly (browser → PDF)
"""

from __future__ import annotations

import html
import os
from datetime import datetime, timezone
from typing import Any

from utils import get_logger

log = get_logger("easm.html_report")

# ── Severity weights for risk score ──────────────────────────────────────
_SEVERITY_WEIGHT = {
    "CRITICAL": 25,
    "HIGH":     10,
    "MEDIUM":   3,
    "LOW":      1,
    "INFO":     0,
}
_SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#65a30d",
    "INFO":     "#0284c7",
}
_SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#f7fee7",
    "INFO":     "#f0f9ff",
}


# ═════════════════════════════════════════════════════════════════════════
#  Finding extraction
# ═════════════════════════════════════════════════════════════════════════

def _add(findings: list[dict], severity: str, title: str, detail: str = "",
         category: str = "", evidence: Any = None):
    findings.append({
        "severity": severity,
        "title": title,
        "detail": detail,
        "category": category,
        "evidence": evidence,
    })


def extract_findings(results: dict) -> list[dict]:
    """Walk the scan results and turn them into severity-tagged findings."""
    f: list[dict] = []

    # ── Attack surface ──
    asurf = results.get("attack_surface", {}) or {}
    for host in asurf.get("open_ports", []) or []:
        for p in host.get("open_ports", []) or []:
            port = p.get("port")
            svc = p.get("service", "")
            cat = p.get("category", "")
            if cat == "database":
                _add(f, "HIGH", f"Database port {port}/{svc} exposed",
                     f"{host.get('hostname','')}:{port} — databases should never be reachable from the public internet.",
                     "Attack Surface", host.get("hostname"))
            elif port in (22, 3389, 23):
                _add(f, "MEDIUM", f"Remote-admin port {port}/{svc} reachable",
                     f"{host.get('hostname','')}:{port}",
                     "Attack Surface", host.get("hostname"))
            elif port in (445, 139):
                _add(f, "HIGH", f"SMB port {port} exposed",
                     f"{host.get('hostname','')}:{port}",
                     "Attack Surface", host.get("hostname"))
            elif cat == "monitoring":
                _add(f, "MEDIUM", f"SNMP port {port} exposed",
                     "SNMP can leak system info if community strings are weak.",
                     "Attack Surface", host.get("hostname"))

    for cve in asurf.get("cves", []) or []:
        sev = (cve.get("severity") or "MEDIUM").upper()
        if sev not in _SEVERITY_WEIGHT:
            sev = "MEDIUM"
        _add(f, sev, f"CVE: {cve.get('id', 'unknown')}",
             cve.get("description", ""), "Attack Surface", cve)

    for portal in asurf.get("login_portals", []) or []:
        _add(f, "INFO", f"Login portal: {portal.get('type','generic')}",
             portal.get("url", ""), "Attack Surface")

    mt = asurf.get("malicious_traffic", {}) or {}
    for bl in mt.get("blacklisted_ips", []) or []:
        _add(f, "HIGH", f"IP blacklisted: {bl.get('ip')}",
             f"Host {bl.get('hostname','')} appears on {len(bl.get('blacklists',[]))} DNSBL(s).",
             "Reputation", bl)

    for leak in asurf.get("cloud_leaks", []) or []:
        if leak.get("access") == "public":
            _add(f, "CRITICAL", f"Public cloud bucket: {leak.get('provider')}",
                 leak.get("url", ""), "Cloud", leak)
        elif leak.get("status_code") and leak["status_code"] < 400:
            _add(f, "HIGH", f"Reachable cloud bucket: {leak.get('provider')}",
                 leak.get("url", ""), "Cloud", leak)

    # ── DNS configuration ──
    dns_cfg = results.get("dns_configuration", {}) or {}
    op = dns_cfg.get("operative_security", {}) or {}
    if not (op.get("dnssec", {}) or {}).get("enabled"):
        _add(f, "MEDIUM", "DNSSEC not enabled",
             "Without DNSSEC, attackers can spoof DNS responses for this domain.",
             "DNS")
    for ns in (op.get("zone_transfer", {}) or {}).get("vulnerable_ns", []) or []:
        _add(f, "CRITICAL", f"AXFR zone transfer allowed: {ns}",
             "All DNS records of this zone can be downloaded by anyone.",
             "DNS", ns)

    admin = dns_cfg.get("administrative_security", {}) or {}
    if not (admin.get("caa_records", {}) or {}).get("has_caa"):
        _add(f, "LOW", "No CAA record",
             "Any CA can issue certificates for this domain.",
             "DNS")
    whois = admin.get("whois_protection", {}) or {}
    if whois.get("expiration_date"):
        try:
            exp = whois["expiration_date"]
            if isinstance(exp, list): exp = exp[0]
            exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
            days_left = (exp_dt - datetime.now(timezone.utc)).days
            if days_left < 30:
                _add(f, "HIGH", f"Domain expires in {days_left} days",
                     f"Expiration: {exp}", "DNS")
            elif days_left < 90:
                _add(f, "LOW", f"Domain expires in {days_left} days",
                     f"Expiration: {exp}", "DNS")
        except Exception:
            pass

    # ── Mail configuration ──
    mail = results.get("mail_configuration", {}) or {}
    if not (mail.get("spf", {}) or {}).get("has_spf"):
        _add(f, "HIGH", "No SPF record",
             "Without SPF, attackers can spoof emails from this domain.", "Mail")
    elif (mail.get("spf", {}) or {}).get("all_qualifier") not in ("-all", "~all"):
        _add(f, "MEDIUM", "Weak SPF policy",
             f"Qualifier: {mail['spf'].get('all_qualifier')}", "Mail")

    if not (mail.get("dkim", {}) or {}).get("has_dkim"):
        _add(f, "MEDIUM", "No DKIM record found",
             "Without DKIM, recipients cannot cryptographically verify your mail.", "Mail")

    dmarc = mail.get("dmarc", {}) or {}
    if not dmarc.get("has_dmarc"):
        _add(f, "HIGH", "No DMARC record",
             "Without DMARC, spoofed mail cannot be reliably blocked.", "Mail")
    else:
        pol = (dmarc.get("policy") or "").lower()
        if pol == "none":
            _add(f, "MEDIUM", "DMARC policy is 'none'",
                 "Domain is monitored but spoofing is not actively blocked.", "Mail")
        elif pol == "quarantine":
            _add(f, "LOW", "DMARC policy is 'quarantine'",
                 "Spoofed mail goes to spam — not rejected.", "Mail")

    for entry in mail.get("mail_blacklists", []) or []:
        listed = entry.get("listed_on", []) or []
        if listed:
            _add(f, "HIGH", f"Mail server blacklisted: {entry.get('mx_hostname')}",
                 f"Listed on: {', '.join(listed)}", "Mail")

    for tls in mail.get("mail_tls", []) or []:
        if not tls.get("starttls_supported"):
            _add(f, "MEDIUM", f"No STARTTLS on {tls.get('hostname')}",
                 "Mail traffic to this server is not encrypted in transit.", "Mail")
        elif tls.get("tls_version") in ("TLSv1.0", "TLSv1.1", "SSLv3"):
            _add(f, "HIGH", f"Outdated TLS on {tls.get('hostname')}",
                 f"Version {tls['tls_version']} is deprecated.", "Mail")

    # ── Privacy & reputation ──
    pr = results.get("privacy_reputation", {}) or {}
    web_tls = pr.get("web_tls", {}) or {}
    cert = web_tls.get("certificate", {}) or {}
    if cert.get("is_expired"):
        _add(f, "CRITICAL", "TLS certificate expired",
             f"Subject: {cert.get('subject', {}).get('commonName','?')}", "Web TLS")
    elif (cert.get("days_until_expiry") or 99) < 14:
        _add(f, "HIGH", f"TLS cert expires in {cert.get('days_until_expiry')} days",
             "", "Web TLS")
    elif (cert.get("days_until_expiry") or 99) < 30:
        _add(f, "MEDIUM", f"TLS cert expires in {cert.get('days_until_expiry')} days",
             "", "Web TLS")
    if cert.get("is_self_signed"):
        _add(f, "HIGH", "Self-signed TLS certificate", "", "Web TLS")
    if (cert.get("key_size") or 4096) < 2048:
        _add(f, "HIGH", f"Weak TLS key size: {cert.get('key_size')} bit", "", "Web TLS")
    for dep in web_tls.get("deprecated_protocols", []) or []:
        _add(f, "HIGH", f"Deprecated protocol enabled: {dep}", "", "Web TLS")

    sec_hdr = pr.get("security_headers", {}) or {}
    for missing in sec_hdr.get("headers_missing", []) or []:
        sev = "LOW"
        if missing in ("Strict-Transport-Security", "Content-Security-Policy"):
            sev = "MEDIUM"
        _add(f, sev, f"Missing security header: {missing}", "", "Web Security")

    rep = pr.get("reputation", {}) or {}
    gsb = rep.get("google_safe_browsing", {}) or {}
    if gsb.get("checked") and not gsb.get("safe"):
        _add(f, "CRITICAL", "Domain flagged by Google Safe Browsing",
             f"Threats: {gsb.get('threats', [])}", "Reputation")
    vt = (rep.get("virustotal", {}) or {}).get("stats", {}) or {}
    if (vt.get("malicious") or 0) > 0:
        _add(f, "HIGH", f"VirusTotal: {vt['malicious']} engines flagged this domain",
             "", "Reputation")

    trackers = pr.get("trackers", {}) or {}
    if trackers.get("trackers_found") and not trackers.get("cookie_banner_found"):
        names = ", ".join(t.get("name", "") for t in trackers["trackers_found"])
        _add(f, "MEDIUM", "Trackers without cookie banner (GDPR risk)",
             f"Detected: {names}", "Privacy")

    # ── Darknet / OSINT ──
    osint = results.get("darknet_osint", {}) or {}
    for leak in osint.get("leaks_found", []) or []:
        _add(f, "HIGH", f"Credential leak: {leak.get('source','unknown')}",
             leak.get("description", ""), "OSINT", leak)
    breaches = osint.get("breach_summary", []) or []
    if breaches:
        _add(f, "MEDIUM", f"Domain appears in {len(breaches)} known breach(es)",
             ", ".join(b.get("name", "") for b in breaches[:5]), "OSINT", breaches)

    # ── Active exploitation ──
    exp = results.get("active_exploitation", {}) or {}
    for vuln in (exp.get("vulnerabilities", []) or []):
        sev = (vuln.get("severity") or "HIGH").upper()
        if sev not in _SEVERITY_WEIGHT:
            sev = "HIGH"
        _add(f, sev, vuln.get("type", "Vulnerability"),
             vuln.get("description", "") or vuln.get("url", ""),
             "Exploitation", vuln)

    # ── Subdomain takeover ──
    takeovers = results.get("subdomain_takeover", {}) or {}
    for t in takeovers.get("vulnerable", []) or []:
        _add(f, "CRITICAL", f"Subdomain takeover possible: {t.get('subdomain')}",
             f"Service: {t.get('service')} — {t.get('reason','')}",
             "Subdomain Takeover", t)

    # ── JS secrets ──
    secrets = results.get("js_secrets", {}) or {}
    for s in secrets.get("findings", []) or []:
        _add(f, "CRITICAL", f"Secret leaked: {s.get('type')}",
             f"{s.get('url','')} — {s.get('match','')[:80]}",
             "JS Secrets", s)

    # ── Web asset intelligence ──
    wai = results.get("web_asset_intelligence", {}) or {}
    for item in wai.get("exposed_artifacts", []) or []:
        sev = (item.get("severity") or "MEDIUM").upper()
        if sev not in _SEVERITY_WEIGHT:
            sev = "MEDIUM"
        _add(f, sev, f"Exposed web artifact: {item.get('path')}",
             f"{item.get('url','')} returned HTTP {item.get('status')}",
             "Web Asset Intel", item)

    for item in wai.get("admin_panels", []) or []:
        sev = (item.get("severity") or "INFO").upper()
        if sev not in _SEVERITY_WEIGHT:
            sev = "INFO"
        _add(f, sev, f"Admin/dev panel exposed: {item.get('path')}",
             f"{item.get('url','')} returned HTTP {item.get('status')}",
             "Web Asset Intel", item)

    for item in wai.get("api_docs", []) or []:
        sev = (item.get("severity") or "INFO").upper()
        if sev not in _SEVERITY_WEIGHT:
            sev = "INFO"
        _add(f, sev, f"API metadata exposed: {item.get('path')}",
             f"{item.get('url','')} — {item.get('evidence','')}",
             "Web Asset Intel", item)

    for item in wai.get("cors_issues", []) or []:
        sev = (item.get("severity") or "MEDIUM").upper()
        if sev not in _SEVERITY_WEIGHT:
            sev = "MEDIUM"
        _add(f, sev, "Permissive CORS policy",
             f"{item.get('url','')} allows origin {item.get('allow_origin','')}",
             "Web Asset Intel", item)

    for item in wai.get("cookie_issues", []) or []:
        sev = (item.get("severity") or "LOW").upper()
        if sev not in _SEVERITY_WEIGHT:
            sev = "LOW"
        _add(f, sev, f"Weak cookie flags: {item.get('cookie')}",
             f"{item.get('url','')} missing {', '.join(item.get('missing', []) or [])}",
             "Web Asset Intel", item)

    return f


# ═════════════════════════════════════════════════════════════════════════
#  Risk score
# ═════════════════════════════════════════════════════════════════════════

def calculate_risk_score(findings: list[dict]) -> tuple[int, str]:
    """Return (score 0-100, label)."""
    raw = sum(_SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    score = min(100, raw)
    if score >= 70:
        label = "CRITICAL"
    elif score >= 40:
        label = "HIGH"
    elif score >= 20:
        label = "MEDIUM"
    elif score >= 5:
        label = "LOW"
    else:
        label = "MINIMAL"
    return score, label


# ═════════════════════════════════════════════════════════════════════════
#  HTML rendering
# ═════════════════════════════════════════════════════════════════════════

_CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       margin: 0; padding: 0; background: #f8fafc; color: #0f172a; line-height: 1.55; }
.container { max-width: 1100px; margin: 0 auto; padding: 24px; }
header.cover { background: linear-gradient(135deg, #101828, #0f766e 62%, #1f2937); color: white;
               padding: 48px 32px; border-radius: 8px; margin-bottom: 24px;
               box-shadow: 0 10px 30px rgba(0,0,0,.15); }
header.cover h1 { margin: 0 0 8px; font-size: 32px; letter-spacing: 0; }
header.cover .domain { font-family: 'SF Mono', Menlo, monospace; font-size: 22px; color: #fbbf24; }
header.cover .meta { margin-top: 16px; color: #94a3b8; font-size: 13px; }
.card { background: white; border-radius: 8px; padding: 24px; margin-bottom: 18px;
        box-shadow: 0 2px 8px rgba(0,0,0,.04); border: 1px solid #e2e8f0; }
.card h2 { margin: 0 0 16px; font-size: 20px; color: #1e293b;
           border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
.card h3 { margin: 18px 0 10px; font-size: 15px; color: #475569; }
.score { display: flex; align-items: center; gap: 24px; }
.score-circle { flex: 0 0 140px; height: 140px; border-radius: 50%;
                display: flex; flex-direction: column; align-items: center; justify-content: center;
                color: white; font-weight: 700; }
.score-circle .num { font-size: 42px; line-height: 1; }
.score-circle .lbl { font-size: 12px; opacity: .9; margin-top: 4px; letter-spacing: 1.5px; }
.severity-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 12px 0; }
.sev-tile { padding: 14px; border-radius: 8px; text-align: center; }
.sev-tile .count { font-size: 28px; font-weight: 700; line-height: 1; }
.sev-tile .name { font-size: 11px; letter-spacing: 1.2px; margin-top: 6px; opacity: .85; }
.findings { margin-top: 8px; }
.finding { padding: 12px 16px; border-left: 4px solid #cbd5e1;
           background: #f8fafc; border-radius: 6px; margin-bottom: 8px; }
.finding .head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.finding .title { font-weight: 600; font-size: 14px; color: #0f172a; }
.finding .badge { font-size: 10px; padding: 3px 10px; border-radius: 999px;
                  font-weight: 700; letter-spacing: 1px; color: white; }
.finding .detail { font-size: 13px; color: #475569; margin-top: 4px; }
.finding .cat { font-size: 11px; color: #64748b; margin-top: 2px; }
table.kv { width: 100%; border-collapse: collapse; font-size: 13px; }
table.kv td { padding: 6px 10px; border-bottom: 1px solid #f1f5f9; }
table.kv td:first-child { color: #64748b; width: 220px; font-weight: 500; }
table.data { width: 100%; border-collapse: collapse; font-size: 12px; }
table.data th { background: #f1f5f9; padding: 8px; text-align: left; font-size: 11px;
                text-transform: uppercase; letter-spacing: 1px; color: #475569; }
table.data td { padding: 7px 8px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
.pill { display: inline-block; padding: 2px 8px; border-radius: 4px;
        font-size: 11px; background: #e0e7ff; color: #3730a3; margin-right: 4px; }
.muted { color: #64748b; font-size: 12px; }
.ok { color: #16a34a; font-weight: 600; }
.bad { color: #dc2626; font-weight: 600; }
footer { text-align: center; color: #94a3b8; font-size: 11px; margin: 32px 0 16px; }
@media print {
  body { background: white; }
  .card { box-shadow: none; page-break-inside: avoid; }
  header.cover { background: #1e293b !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .sev-tile, .finding, .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
"""


def _e(s: Any) -> str:
    return html.escape(str(s) if s is not None else "")


def _badge(severity: str) -> str:
    color = _SEVERITY_COLOR.get(severity, "#64748b")
    return f'<span class="badge" style="background:{color}">{_e(severity)}</span>'


def _render_finding(f: dict) -> str:
    color = _SEVERITY_COLOR.get(f["severity"], "#cbd5e1")
    bg = _SEVERITY_BG.get(f["severity"], "#f8fafc")
    return f"""<div class="finding" style="border-left-color:{color};background:{bg}">
        <div class="head">
            <span class="title">{_e(f['title'])}</span>
            {_badge(f['severity'])}
        </div>
        {f'<div class="detail">{_e(f["detail"])}</div>' if f.get('detail') else ''}
        {f'<div class="cat">{_e(f["category"])}</div>' if f.get('category') else ''}
    </div>"""


def _render_score(score: int, label: str, findings: list[dict]) -> str:
    color = _SEVERITY_COLOR.get(label, "#64748b")
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    tiles = "".join(
        f'<div class="sev-tile" style="background:{_SEVERITY_BG[s]};color:{_SEVERITY_COLOR[s]};border:1px solid {_SEVERITY_COLOR[s]}33">'
        f'<div class="count">{counts[s]}</div><div class="name">{s}</div></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    return f"""<div class="card">
      <h2>Risk Overview</h2>
      <div class="score">
        <div class="score-circle" style="background:{color}">
          <div class="num">{score}</div>
          <div class="lbl">{_e(label)} RISK</div>
        </div>
        <div style="flex:1">
          <div class="severity-grid">{tiles}</div>
          <div class="muted">Total findings: <strong>{len(findings)}</strong></div>
        </div>
      </div>
    </div>"""


def _render_attack_surface(asurf: dict) -> str:
    if not asurf:
        return ""
    hd = asurf.get("host_discovery", {}) or {}
    subs = hd.get("subdomains", []) or []
    hosts = hd.get("hosts", []) or []
    ports = asurf.get("open_ports", []) or []
    sw = asurf.get("software", {}) or {}

    rows = []
    for h in hosts[:50]:
        rows.append(f"<tr><td>{_e(h.get('hostname'))}</td>"
                    f"<td><code>{_e(h.get('ip'))}</code></td>"
                    f"<td>{' '.join(f'<span class=\"pill\">{_e(r)}</span>' for r in h.get('roles',[]))}</td></tr>")
    hosts_table = "<table class='data'><tr><th>Hostname</th><th>IP</th><th>Roles</th></tr>" + "".join(rows) + "</table>" if rows else ""

    port_rows = []
    for h in ports:
        for p in h.get("open_ports", []) or []:
            port_rows.append(f"<tr><td>{_e(h.get('hostname'))}</td>"
                             f"<td><code>{_e(p.get('port'))}/{_e(p.get('protocol','tcp'))}</code></td>"
                             f"<td>{_e(p.get('service'))}</td>"
                             f"<td>{_e(p.get('product'))} {_e(p.get('version'))}</td></tr>")
    ports_table = "<table class='data'><tr><th>Host</th><th>Port</th><th>Service</th><th>Software</th></tr>" + "".join(port_rows) + "</table>" if port_rows else "<div class='muted'>No open ports detected.</div>"

    web_servers = sw.get("webservers", []) or []
    cms = sw.get("cms", []) or []
    sw_html = ""
    if web_servers or cms:
        sw_lines = []
        for w in web_servers[:10]:
            sw_lines.append(f"<li><span class='pill'>WEB</span> <code>{_e(w.get('server'))}</code> — {_e(w.get('url'))}</li>")
        for c in cms[:10]:
            sw_lines.append(f"<li><span class='pill'>CMS</span> <code>{_e(c.get('cms'))} {_e(c.get('version'))}</code> — {_e(c.get('url'))}</li>")
        sw_html = "<h3>Detected Software</h3><ul>" + "".join(sw_lines) + "</ul>"

    sub_html = ""
    if subs:
        sub_html = ("<h3>Subdomains discovered (" + str(len(subs)) + ")</h3>"
                    "<div style='font-family:Menlo,monospace;font-size:11px;column-count:3;column-gap:18px'>"
                    + "".join(f"<div>{_e(s)}</div>" for s in subs) + "</div>")

    return f"""<div class="card">
      <h2>Attack Surface</h2>
      {sub_html}
      <h3>Hosts ({len(hosts)})</h3>{hosts_table}
      <h3>Open Ports</h3>{ports_table}
      {sw_html}
    </div>"""


def _render_dns(dns_cfg: dict) -> str:
    if not dns_cfg:
        return ""
    op = dns_cfg.get("operative_security", {}) or {}
    admin = dns_cfg.get("administrative_security", {}) or {}
    whois = admin.get("whois_protection", {}) or {}
    dnssec = (op.get("dnssec", {}) or {}).get("enabled")
    caa = (admin.get("caa_records", {}) or {}).get("has_caa")
    vuln_ns = (op.get("zone_transfer", {}) or {}).get("vulnerable_ns", []) or []
    return f"""<div class="card">
      <h2>DNS Configuration</h2>
      <table class="kv">
        <tr><td>Registrar</td><td>{_e(whois.get('registrar'))}</td></tr>
        <tr><td>Created</td><td>{_e(whois.get('creation_date'))}</td></tr>
        <tr><td>Expires</td><td>{_e(whois.get('expiration_date'))}</td></tr>
        <tr><td>DNSSEC</td><td>{'<span class="ok">enabled</span>' if dnssec else '<span class="bad">disabled</span>'}</td></tr>
        <tr><td>CAA records</td><td>{'<span class="ok">present</span>' if caa else '<span class="bad">missing</span>'}</td></tr>
        <tr><td>Zone transfer (AXFR)</td><td>{'<span class="bad">VULNERABLE: '+_e(', '.join(vuln_ns))+'</span>' if vuln_ns else '<span class="ok">blocked</span>'}</td></tr>
      </table>
    </div>"""


def _render_mail(mail: dict) -> str:
    if not mail:
        return ""
    spf = mail.get("spf", {}) or {}
    dkim = mail.get("dkim", {}) or {}
    dmarc = mail.get("dmarc", {}) or {}

    def yn(b): return '<span class="ok">yes</span>' if b else '<span class="bad">no</span>'

    return f"""<div class="card">
      <h2>Mail Configuration</h2>
      <table class="kv">
        <tr><td>SPF</td><td>{yn(spf.get('has_spf'))} — qualifier <code>{_e(spf.get('all_qualifier'))}</code></td></tr>
        <tr><td>DKIM</td><td>{yn(dkim.get('has_dkim'))} — selectors: {len(dkim.get('found_selectors', []) or [])}</td></tr>
        <tr><td>DMARC</td><td>{yn(dmarc.get('has_dmarc'))} — policy <code>{_e(dmarc.get('policy'))}</code></td></tr>
      </table>
      {f'<div class="muted" style="margin-top:8px"><strong>SPF:</strong> <code>{_e(spf.get("record"))}</code></div>' if spf.get("record") else ''}
      {f'<div class="muted"><strong>DMARC:</strong> <code>{_e(dmarc.get("record"))}</code></div>' if dmarc.get("record") else ''}
    </div>"""


def _render_web(pr: dict) -> str:
    if not pr:
        return ""
    cert = (pr.get("web_tls", {}) or {}).get("certificate", {}) or {}
    sec = pr.get("security_headers", {}) or {}
    missing = sec.get("headers_missing", []) or []
    present = list((sec.get("headers_present", {}) or {}).keys())

    return f"""<div class="card">
      <h2>Web Security & Privacy</h2>
      <h3>TLS Certificate</h3>
      <table class="kv">
        <tr><td>Subject</td><td>{_e((cert.get('subject') or {}).get('commonName'))}</td></tr>
        <tr><td>Issuer</td><td>{_e((cert.get('issuer') or {}).get('organizationName'))}</td></tr>
        <tr><td>Expires</td><td>{_e(cert.get('not_after'))} ({_e(cert.get('days_until_expiry'))} days)</td></tr>
        <tr><td>Key</td><td>{_e(cert.get('key_alg'))} {_e(cert.get('key_size'))} bit</td></tr>
      </table>
      <h3>Security Headers</h3>
      <div>{''.join(f'<span class="pill" style="background:#dcfce7;color:#166534">{_e(h)}</span>' for h in present) or '<span class="muted">none</span>'}</div>
      <div style="margin-top:8px">{''.join(f'<span class="pill" style="background:#fee2e2;color:#991b1b">{_e(h)}</span>' for h in missing)}</div>
    </div>"""


def _render_web_asset_intel(wai: dict) -> str:
    if not wai:
        return ""
    assets = wai.get("live_assets", []) or []
    api_docs = wai.get("api_docs", []) or []
    panels = wai.get("admin_panels", []) or []
    artifacts = wai.get("exposed_artifacts", []) or []
    cors = wai.get("cors_issues", []) or []
    cookies = wai.get("cookie_issues", []) or []

    asset_rows = []
    for a in assets[:50]:
        tech = ", ".join(a.get("technologies", [])[:4])
        asset_rows.append(
            f"<tr><td>{_e(a.get('host'))}</td>"
            f"<td><code>{_e(a.get('status'))}</code></td>"
            f"<td>{_e(a.get('title'))}</td>"
            f"<td>{_e(tech)}</td></tr>"
        )
    asset_table = (
        "<table class='data'><tr><th>Host</th><th>Status</th><th>Title</th><th>Tech</th></tr>"
        + "".join(asset_rows) + "</table>"
        if asset_rows else "<div class='muted'>No live web assets detected.</div>"
    )

    def small_table(items: list[dict], label: str) -> str:
        if not items:
            return ""
        rows = []
        for item in items[:30]:
            rows.append(
                f"<tr><td><code>{_e(item.get('status', ''))}</code></td>"
                f"<td>{_e(item.get('severity', ''))}</td>"
                f"<td>{_e(item.get('path', ''))}</td>"
                f"<td>{_e(item.get('url', ''))}</td></tr>"
            )
        return (
            f"<h3>{_e(label)} ({len(items)})</h3>"
            "<table class='data'><tr><th>Status</th><th>Severity</th><th>Path</th><th>URL</th></tr>"
            + "".join(rows) + "</table>"
        )

    extras = (
        small_table(artifacts, "Exposed Artifacts")
        + small_table(panels, "Admin / Dev Panels")
        + small_table(api_docs, "API Metadata")
    )
    signal_line = (
        f"<div class='muted' style='margin-top:8px'>"
        f"CORS issues: <strong>{len(cors)}</strong> · Cookie flag issues: <strong>{len(cookies)}</strong>"
        f"</div>"
    )

    return f"""<div class="card">
      <h2>Web Asset Intelligence</h2>
      <div class="muted">Live assets: <strong>{len(assets)}</strong> · Candidate hosts: <strong>{_e(wai.get('candidate_hosts', 0))}</strong></div>
      <h3>Live Web Assets</h3>{asset_table}
      {extras}
      {signal_line}
    </div>"""


def _render_findings_section(findings: list[dict]) -> str:
    if not findings:
        return '<div class="card"><h2>Findings</h2><div class="muted">No issues found.</div></div>'
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    findings_sorted = sorted(findings, key=lambda f: (order.index(f["severity"]) if f["severity"] in order else 99, f["title"]))
    body = "".join(_render_finding(f) for f in findings_sorted)
    return f'<div class="card"><h2>All Findings ({len(findings)})</h2><div class="findings">{body}</div></div>'


def render_html(domain: str, results: dict, scan_date: str = "") -> str:
    findings = extract_findings(results)
    score, label = calculate_risk_score(findings)
    if not scan_date:
        scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sections = [
        _render_score(score, label, findings),
        _render_attack_surface(results.get("attack_surface", {}) or {}),
        _render_dns(results.get("dns_configuration", {}) or {}),
        _render_mail(results.get("mail_configuration", {}) or {}),
        _render_web(results.get("privacy_reputation", {}) or {}),
        _render_web_asset_intel(results.get("web_asset_intelligence", {}) or {}),
        _render_findings_section(findings),
    ]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>link-ed.it CyberScan Report - {_e(domain)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <header class="cover">
    <div style="font-size:11px;letter-spacing:3px;color:#d9e3ef">LINK-ED.IT INTERNAL CYBERSCAN</div>
    <h1>Customer Security Assessment</h1>
    <div class="domain">{_e(domain)}</div>
    <div class="meta">Generated {_e(scan_date)} · link-ed.it CyberScan v2 · Internal</div>
  </header>
  {''.join(sections)}
  <footer>link-ed.it CyberScan - confidential internal security assessment for {_e(domain)}</footer>
</div>
<script>
  if (new URLSearchParams(window.location.search).get("print") === "1") {{
    window.addEventListener("load", () => setTimeout(() => window.print(), 250));
  }}
</script>
</body>
</html>"""


def write_html_report(domain: str, results: dict, output_dir: str = "results",
                      scan_date: str = "") -> str:
    target_dir = os.path.join(output_dir, domain)
    os.makedirs(target_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(target_dir, f"{ts}.html")
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(render_html(domain, results, scan_date=scan_date))
    log.info(f"HTML report written: {path}")
    return path
