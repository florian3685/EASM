"""
EASM Scanner — Report Generator
==================================
Generates machine-readable JSON reports for deep reconnaissance and vulnerability scanning.
Highlights dumped credentials and extracted user/password data from the Data Extractor profile.
"""

import json
import os
import textwrap
from datetime import datetime, timezone

from utils import get_logger

log = get_logger("easm.report")


def _pdf_escape(value: object) -> str:
    text = str(value if value is not None else "")
    text = text.replace("\r", " ").replace("\n", " ")
    text = text.encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_pages(lines: list[str], width: int = 92, height: int = 48) -> list[list[str]]:
    wrapped: list[str] = []
    for line in lines:
        if not line:
            wrapped.append("")
            continue
        wrapped.extend(textwrap.wrap(line, width=width, replace_whitespace=False) or [""])
    return [wrapped[i:i + height] for i in range(0, len(wrapped), height)] or [[""]]


def _write_simple_pdf(path: str, lines: list[str]) -> None:
    pages = _pdf_pages(lines)
    objects: list[bytes] = [b""]
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    kids: list[int] = []

    for page_lines in pages:
        commands = ["BT", "/F1 10 Tf", "50 800 Td", "14 TL"]
        for line in page_lines:
            commands.append(f"({_pdf_escape(line)}) Tj")
            commands.append("T*")
        commands.append("ET")
        content = "\n".join(commands).encode("latin-1", "replace")
        stream = (
            f"<< /Length {len(content)} >>\nstream\n".encode("ascii")
            + content
            + b"\nendstream"
        )
        content_num = len(objects)
        objects.append(stream)
        page_num = len(objects)
        kids.append(page_num)
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_num} 0 R >>"
            ).encode("ascii")
        )

    kid_refs = " ".join(f"{kid} 0 R" for kid in kids)
    objects[2] = f"<< /Type /Pages /Kids [{kid_refs}] /Count {len(kids)} >>".encode("ascii")

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number in range(1, len(objects)):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode("ascii"))
        pdf.extend(objects[number])
        pdf.extend(b"\nendobj\n")

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(objects)}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        (
            f"trailer\n<< /Size {len(objects)} /Root 1 0 R >>\n"
            f"startxref\n{xref_start}\n%%EOF\n"
        ).encode("ascii")
    )

    with open(path, "wb") as handle:
        handle.write(pdf)


class ReportGenerator:
    """Generates JSON, HTML and PDF CyberScan reports."""

    CATEGORY_NAMES = {
        "attack_surface":            "1. Attack Surface",
        "infrastructure_stability":  "2. Infrastructure Stability",
        "dns_configuration":         "3. DNS Configuration",
        "mail_configuration":        "4. Mail Configuration",
        "privacy_reputation":        "5. Privacy & Reputation",
        "darknet_osint":             "6. Darknet / OSINT",
        "advanced_recon":            "7. Advanced Recon",
        "parameter_discovery":       "8. Parameter Fuzzing",
        "github_recon":              "9. GitHub Recon",
        "cloud_assets":              "10. Cloud Assets",
        "active_exploitation":       "11. Active Exploitation",
        "subdomain_takeover":        "12. Subdomain Takeover",
        "js_secrets":                "13. JS Secrets Scanner",
        "web_asset_intelligence":    "14. Web Asset Intelligence",
    }

    def __init__(self, domain: str, results: dict):
        self.domain = domain
        self.results = results
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def _extract_dumped_data(self) -> dict:
        """Pull out extracted credentials and DB dumps from exploitation results."""
        dumped = {"databases_breached": [], "credentials_found": [], "sqli_dumps": []}

        exploit_data = self.results.get("active_exploitation", {})
        if not exploit_data or isinstance(exploit_data, str):
            return dumped

        for vuln in exploit_data.get("vulnerabilities", []):
            vtype = vuln.get("type", "")

            if "Database Breach" in vtype:
                entry = {
                    "type": vtype,
                    "host": vuln.get("host", ""),
                    "port": vuln.get("port", ""),
                    "schema": vuln.get("dumped_schema", []),
                }
                dumped["databases_breached"].append(entry)

                creds = vuln.get("extracted_credentials", [])
                if creds:
                    dumped["credentials_found"].extend(creds)

            if "SQL Injection" in vtype:
                dumped["sqli_dumps"].append({
                    "param": vuln.get("param", ""),
                    "url": vuln.get("url", ""),
                    "severity": vuln.get("severity", ""),
                    "dump_indicators": vuln.get("dump_indicators", []),
                })

        return dumped

    def generate_html(self, output_dir: str = "results") -> str:
        """Generate the customer-facing HTML report."""
        from html_report import write_html_report
        return write_html_report(self.domain, self.results, output_dir=output_dir,
                                 scan_date=self.timestamp)

    def generate_pdf(self, output_dir: str = "results") -> str:
        """Generate a compact PDF executive report without external dependencies."""
        from html_report import calculate_risk_score, extract_findings

        findings = extract_findings(self.results)
        score, label = calculate_risk_score(findings)
        counts = {
            severity: sum(1 for finding in findings if finding.get("severity") == severity)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        }
        lines = [
            "link-ed.it CyberScan - Internal Security Report",
            f"Customer domain: {self.domain}",
            f"Generated: {self.timestamp}",
            f"Risk score: {score}/100 ({label})",
            "",
            "Finding summary",
            f"Critical: {counts['CRITICAL']}  High: {counts['HIGH']}  Medium: {counts['MEDIUM']}  Low: {counts['LOW']}  Info: {counts['INFO']}",
            "",
            "Top findings",
        ]

        for finding in findings[:45]:
            severity = finding.get("severity", "INFO")
            title = finding.get("title", "Finding")
            detail = finding.get("detail", "")
            category = finding.get("category", "")
            lines.append(f"[{severity}] {title}")
            if category:
                lines.append(f"Category: {category}")
            if detail:
                lines.append(f"Detail: {detail}")
            lines.append("")

        if not findings:
            lines.append("No findings were extracted from the selected scan modules.")

        lines.extend([
            "",
            "Scope note",
            "This report is generated for internal link-ed.it work on authorized customer domains.",
            "Use the JSON report for machine processing and the HTML report for detailed browser review.",
        ])

        target_dir = os.path.join(output_dir, self.domain)
        os.makedirs(target_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(target_dir, f"{ts}.pdf")
        _write_simple_pdf(filepath, lines)
        log.info(f"PDF report saved: {filepath}")
        return filepath

    def generate_json(self, output_dir: str = "results") -> str:
        """Generate the JSON report in a domain-specific subdirectory."""
        report = {
            "meta": {
                "scanner": "link-ed.it CyberScan v2.0",
                "company": "link-ed.it",
                "classification": "internal",
                "authorized_customer_scan": True,
                "domain": self.domain,
                "scan_date": self.timestamp,
                "formats": ["json", "html", "pdf"],
                "categories": list(self.CATEGORY_NAMES.keys()),
            },
            "attack_surface": self.results.get("attack_surface", {}),
            "infrastructure_stability": self.results.get("infrastructure_stability", {}),
            "dns_configuration": self.results.get("dns_configuration", {}),
            "mail_configuration": self.results.get("mail_configuration", {}),
            "privacy_reputation": self.results.get("privacy_reputation", {}),
            "darknet_osint": self.results.get("darknet_osint", {}),
            "advanced_recon": self.results.get("advanced_recon", {}),
            "parameter_discovery": self.results.get("parameter_discovery", {}),
            "github_recon": self.results.get("github_recon", {}),
            "cloud_assets": self.results.get("cloud_assets", {}),
            "active_exploitation": self.results.get("active_exploitation", {}),
            "subdomain_takeover": self.results.get("subdomain_takeover", {}),
            "js_secrets": self.results.get("js_secrets", {}),
            "web_asset_intelligence": self.results.get("web_asset_intelligence", {}),
            "dumped_data": self._extract_dumped_data(),
        }

        # Directory structure: <output_dir>/<domain>/
        target_dir = os.path.join(output_dir, self.domain)
        os.makedirs(target_dir, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{ts}.json"
        filepath = os.path.join(target_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2, default=str)

        log.info(f"JSON report saved: {filepath}")
        return filepath
