"""
EASM Scanner — Report Generator
==================================
Generates machine-readable JSON reports for deep reconnaissance and vulnerability scanning.
Highlights dumped credentials and extracted user/password data from the Data Extractor profile.
"""

import json
import os
import textwrap
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from utils import get_logger

log = get_logger("easm.report")

try:
    from PIL import Image, ImageDraw, ImageFont
except Exception:  # pragma: no cover - PDF generation falls back if Pillow is unavailable.
    Image = ImageDraw = ImageFont = None


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


_PDF_COLORS = {
    "navy": "#17395f",
    "blue": "#1479bd",
    "cyan": "#159cdf",
    "text": "#30343a",
    "muted": "#707780",
    "line": "#c9d3dc",
    "soft": "#eef4f9",
    "soft2": "#e6f0f8",
    "white": "#ffffff",
    "CRITICAL": "#d92700",
    "HIGH": "#e65a00",
    "MEDIUM": "#2f86c7",
    "LOW": "#4caf50",
    "INFO": "#8e8e8e",
}

_SEVERITY_DE = {
    "CRITICAL": "KRITISCH",
    "HIGH": "HOCH",
    "MEDIUM": "MITTEL",
    "LOW": "NIEDRIG",
    "INFO": "INFO",
    "MINIMAL": "MINIMAL",
}

_CATEGORY_DE = {
    "Attack Surface": "Angriffsoberfläche",
    "DNS": "DNS",
    "Mail": "E-Mail",
    "Web TLS": "Web-Sicherheit",
    "Web Security": "Web-Sicherheit",
    "Reputation": "Reputation",
    "Privacy": "Datenschutz",
    "OSINT": "Darknet OSINT",
    "Cloud": "Cloud Assets",
    "GitHub": "GitHub Recon",
    "JavaScript": "JavaScript Secrets",
}


def _font_path(name: str) -> str:
    candidates = [
        f"/usr/share/fonts/truetype/dejavu/{name}",
        f"/usr/share/fonts/truetype/liberation/{name}",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return ""


def _font(size: int, bold: bool = False, mono: bool = False):
    if ImageFont is None:
        return None
    if mono:
        filename = "DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf"
    else:
        filename = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    path = _font_path(filename)
    return ImageFont.truetype(path, size) if path else ImageFont.load_default()


def _logo_path() -> str:
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base, "web", "static", "img", "link-ed.it-logo.png"),
        os.path.join(base, "link-ed.it-logo.png"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return ""


def _date_de(value: str) -> str:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        dt = datetime.now(timezone.utc)
    months = [
        "Januar", "Februar", "März", "April", "Mai", "Juni",
        "Juli", "August", "September", "Oktober", "November", "Dezember",
    ]
    return f"{dt.day}. {months[dt.month - 1]} {dt.year}"


def _clip(value: object, fallback: str = "-") -> str:
    text = str(value if value not in (None, "") else fallback)
    return text.replace("\n", " ").replace("\r", " ").strip()


def _severity_rank(severity: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(str(severity).upper(), 5)


class _StyledPdf:
    """A lightweight image-based A4 renderer matching the linked.it report style."""

    W = 1240
    H = 1754
    M = 118
    TOP = 118
    BOTTOM = 154

    def __init__(self, domain: str):
        self.domain = domain
        self.pages: list[Any] = []
        self.image = None
        self.draw = None
        self.section = ""
        self.y = self.TOP

    @property
    def content_w(self) -> int:
        return self.W - 2 * self.M

    def new_page(self, section: str = "") -> None:
        self.image = Image.new("RGB", (self.W, self.H), _PDF_COLORS["white"])
        self.draw = ImageDraw.Draw(self.image)
        self.section = section
        self.y = self.TOP
        if section:
            self.text_center(64, section, _font(18), _PDF_COLORS["muted"])
        self.pages.append(self.image)

    def save(self, path: str) -> None:
        for idx, page in enumerate(self.pages, start=1):
            if idx == 1:
                continue
            draw = ImageDraw.Draw(page)
            draw.text((self.W / 2, self.H - 64), str(idx), anchor="mm",
                      font=_font(18), fill=_PDF_COLORS["muted"])
        first, *rest = self.pages
        first.save(path, "PDF", save_all=True, append_images=rest, resolution=150.0)

    def ensure(self, needed: int, section: str | None = None) -> None:
        if self.y + needed > self.H - self.BOTTOM:
            self.new_page(section or self.section)

    def text(self, x: int, y: int, text: str, font, fill: str = _PDF_COLORS["text"], anchor: str | None = None) -> None:
        self.draw.text((x, y), str(text), font=font, fill=fill, anchor=anchor)

    def text_center(self, y: int, text: str, font, fill: str = _PDF_COLORS["text"]) -> None:
        self.draw.text((self.W / 2, y), str(text), font=font, fill=fill, anchor="mm")

    def line(self, y: int, color: str = _PDF_COLORS["blue"], width: int = 4) -> None:
        self.draw.line((self.M, y, self.W - self.M, y), fill=color, width=width)

    def title(self, text: str) -> None:
        self.text(self.M, self.y, text, _font(46, bold=True), _PDF_COLORS["navy"])
        self.y += 62
        self.line(self.y, width=4)
        self.y += 34

    def section_heading(self, text: str) -> None:
        self.ensure(58)
        self.draw.rounded_rectangle((self.M, self.y + 2, self.M + 6, self.y + 48), radius=4, fill=_PDF_COLORS["blue"])
        self.text(self.M + 18, self.y, text, _font(30, bold=True), _PDF_COLORS["blue"])
        self.y += 62

    def wrap_lines(self, text: str, font, max_width: int) -> list[str]:
        words = _clip(text, "").split()
        lines: list[str] = []
        current = ""
        for word in words:
            trial = f"{current} {word}".strip()
            width = self.draw.textbbox((0, 0), trial, font=font)[2]
            if width <= max_width or not current:
                current = trial
            else:
                lines.append(current)
                current = word
        if current:
            lines.append(current)
        return lines or [""]

    def paragraph(self, text: str, size: int = 22, color: str = _PDF_COLORS["text"],
                  width: int | None = None, leading: int = 34, bold: bool = False) -> None:
        font = _font(size, bold=bold)
        width = width or self.content_w
        lines = self.wrap_lines(text, font, width)
        self.ensure(len(lines) * leading + 8)
        for line in lines:
            self.text(self.M, self.y, line, font, color)
            self.y += leading

    def info_box(self, title: str, body: str) -> None:
        font_body = _font(21)
        lines = self.wrap_lines(body, font_body, self.content_w - 58)
        height = 84 + len(lines) * 30
        self.ensure(height + 24)
        x1, y1, x2, y2 = self.M, self.y, self.W - self.M, self.y + height
        self.draw.rectangle((x1, y1, x2, y2), fill=_PDF_COLORS["soft"], outline=_PDF_COLORS["line"], width=1)
        self.text(x1 + 30, y1 + 26, title, _font(21, bold=True), _PDF_COLORS["blue"])
        yy = y1 + 84
        for line in lines:
            self.text(x1 + 30, yy, line, font_body, _PDF_COLORS["text"])
            yy += 30
        self.y = y2 + 30

    def simple_table(self, headers: list[str], rows: list[list[str]], widths: list[int] | None = None,
                     max_rows: int | None = None) -> None:
        rows = rows[:max_rows] if max_rows else rows
        if not rows:
            self.paragraph("Keine Daten vorhanden.", size=18, color=_PDF_COLORS["muted"])
            return
        widths = widths or [self.content_w // len(headers)] * len(headers)
        row_h = 58
        header_h = 58
        table_h = header_h + row_h * len(rows)
        self.ensure(table_h + 20)
        x = self.M
        y = self.y
        self.draw.rectangle((x, y, x + sum(widths), y + header_h), fill=_PDF_COLORS["navy"])
        xx = x
        for header, width in zip(headers, widths):
            self.text(xx + 16, y + 18, header.upper(), _font(18, bold=True), _PDF_COLORS["white"])
            xx += width
        y += header_h
        for index, row in enumerate(rows):
            fill = _PDF_COLORS["soft"] if index % 2 else _PDF_COLORS["white"]
            self.draw.rectangle((x, y, x + sum(widths), y + row_h), fill=fill)
            self.draw.line((x, y + row_h, x + sum(widths), y + row_h), fill=_PDF_COLORS["line"], width=1)
            xx = x
            for value, width in zip(row, widths):
                font = _font(17, mono=("." in value or ":" in value))
                color = _PDF_COLORS["blue"] if value.upper() in _SEVERITY_DE.values() else _PDF_COLORS["text"]
                self.text(xx + 16, y + 18, _clip(value), font, color)
                xx += width
            y += row_h
        self.y = y + 28

    def category_grid(self, items: list[str]) -> None:
        if not items:
            return
        cols = 4
        cell_w = self.content_w // cols
        cell_h = 74
        rows = (len(items) + cols - 1) // cols
        self.ensure(rows * cell_h + 20)
        x0 = self.M
        y0 = self.y
        for idx, item in enumerate(items):
            col = idx % cols
            row = idx // cols
            x = x0 + col * cell_w
            y = y0 + row * cell_h
            self.draw.rectangle((x, y, x + cell_w, y + cell_h), fill="#e7f0f8", outline=_PDF_COLORS["white"], width=2)
            lines = self.wrap_lines(item, _font(17, mono=True), cell_w - 22)[:2]
            yy = y + 22
            for line in lines:
                self.text(x + 12, yy, line, _font(17, mono=True), _PDF_COLORS["blue"])
                yy += 24
        self.y += rows * cell_h + 30

    def finding_card(self, finding: dict) -> None:
        severity = str(finding.get("severity", "INFO")).upper()
        title = _clip(finding.get("title", "Finding"))
        detail = _clip(finding.get("detail", ""), "")
        category = _CATEGORY_DE.get(str(finding.get("category", "")), str(finding.get("category", "")) or "Allgemein")
        title_lines = self.wrap_lines(title, _font(20, bold=True), self.content_w - 230)
        detail_lines = self.wrap_lines(detail, _font(17), self.content_w - 38)[:3] if detail else []
        height = 78 + len(title_lines) * 26 + len(detail_lines) * 24
        self.ensure(height + 16)
        x1, y1, x2 = self.M, self.y, self.W - self.M
        color = _PDF_COLORS.get(severity, _PDF_COLORS["INFO"])
        self.draw.rectangle((x1, y1, x2, y1 + height), fill=_PDF_COLORS["white"], outline=_PDF_COLORS["line"], width=1)
        self.draw.rectangle((x1, y1, x1 + 7, y1 + height), fill=color)
        self.draw.rounded_rectangle((x2 - 142, y1 + 20, x2 - 18, y1 + 50), radius=15, fill=color)
        self.text(x2 - 80, y1 + 35, _SEVERITY_DE.get(severity, severity), _font(13, bold=True), _PDF_COLORS["white"], anchor="mm")
        yy = y1 + 20
        for line in title_lines:
            self.text(x1 + 24, yy, line, _font(20, bold=True), _PDF_COLORS["text"])
            yy += 26
        self.text(x1 + 24, yy + 4, category, _font(15), _PDF_COLORS["muted"])
        yy += 32
        for line in detail_lines:
            self.text(x1 + 24, yy, line, _font(17), _PDF_COLORS["muted"])
            yy += 24
        self.y += height + 14


def _extract_report_context(domain: str, results: dict, findings: list[dict]) -> dict[str, Any]:
    asurf = results.get("attack_surface", {}) or {}
    hd = asurf.get("host_discovery", {}) or {}
    hosts = hd.get("hosts", []) or []
    subdomains = hd.get("subdomains", []) or []
    ports = asurf.get("open_ports", []) or []
    open_port_count = sum(len(host.get("open_ports", []) or []) for host in ports)
    categories = sorted({
        _CATEGORY_DE.get(str(f.get("category", "")), str(f.get("category", "")) or "Allgemein")
        for f in findings
    })
    if not categories:
        categories = ["Angriffsoberfläche", "DNS-Konfiguration", "E-Mail-Konfiguration", "Web-Sicherheit"]
    return {
        "domain": domain,
        "hosts": hosts,
        "subdomains": subdomains,
        "open_port_count": open_port_count,
        "categories": categories,
    }


def _generate_styled_pdf(path: str, domain: str, results: dict, scan_date: str) -> None:
    if Image is None:
        raise RuntimeError("Pillow is required for styled PDF generation.")
    from html_report import calculate_risk_score, extract_findings

    findings = extract_findings(results)
    score, label = calculate_risk_score(findings)
    counts = Counter(str(f.get("severity", "INFO")).upper() for f in findings)
    ctx = _extract_report_context(domain, results, findings)
    pdf = _StyledPdf(domain)

    # Cover
    pdf.new_page("")
    logo_drawn = False
    logo_path = _logo_path()
    if logo_path:
        try:
            source = Image.open(logo_path)
            logo = source.convert("RGBA")
            source.close()
            resample = getattr(getattr(Image, "Resampling", Image), "LANCZOS", Image.LANCZOS)
            logo.thumbnail((320, 320), resample)
            pdf.image.paste(logo, ((pdf.W - logo.width) // 2, 405), logo)
            logo_drawn = True
        except Exception:
            logo_drawn = False
    if not logo_drawn:
        pdf.text_center(590, "linked", _font(74, bold=True), _PDF_COLORS["navy"])
        pdf.text_center(680, ".IT", _font(86, bold=True), _PDF_COLORS["cyan"])
    pdf.text_center(835, "CYBERSECURITY ASSESSMENT", _font(22), _PDF_COLORS["cyan"])
    pdf.text_center(900, "EASM Security Assessment", _font(54, bold=True), _PDF_COLORS["navy"])
    pdf.text_center(962, domain, _font(29, mono=True), _PDF_COLORS["cyan"])
    pdf.text_center(1042, "Externe Angriffsoberfläche (EASM)", _font(18), _PDF_COLORS["cyan"])
    pdf.text_center(1084, f"Erstellt am {_date_de(scan_date)}", _font(18), _PDF_COLORS["cyan"])
    pdf.text_center(1126, "Erstellt von: link-ed.IT Consulting & Services", _font(18), _PDF_COLORS["cyan"])
    pdf.text_center(1688, "VERTRAULICH - Nur fuer autorisierte Empfaenger", _font(16), _PDF_COLORS["cyan"])

    # TOC
    pdf.new_page("Inhaltsverzeichnis")
    pdf.title("Inhaltsverzeichnis")
    toc = [
        "1. Zusammenfassung",
        "2. Risikoübersicht",
        "3. Angriffsoberfläche",
        "4. DNS-Konfiguration",
        "5. E-Mail-Konfiguration",
        "6. Web-Sicherheit & Datenschutz",
        "7. Alle Ergebnisse",
        "8. Handlungsempfehlungen",
    ]
    for item in toc:
        pdf.text(pdf.M, pdf.y, item, _font(24), _PDF_COLORS["blue"])
        pdf.y += 42
        pdf.draw.line((pdf.M, pdf.y, pdf.W - pdf.M, pdf.y), fill=_PDF_COLORS["line"], width=1)
        pdf.y += 16

    # Summary
    pdf.new_page("1. Zusammenfassung")
    pdf.title("1. Zusammenfassung")
    pdf.paragraph(
        f"Dieser Bericht enthält die Ergebnisse einer umfassenden Analyse der externen Angriffsoberfläche der Domain "
        f"{domain}. Die Untersuchung wurde am {_date_de(scan_date)} durchgeführt – von außen, so wie es ein Angreifer tun würde. "
        "Kein Penetrationstest, kein Login, kein aktives Ausnutzen von Schwachstellen – nur das, was frei im Internet sichtbar ist.",
        size=21,
        leading=32,
    )
    pdf.y += 18
    pdf.info_box(
        "Gesamtergebnis",
        f"Der Sicherheitsscan hat {len(ctx['subdomains'])} Subdomains, {len(ctx['hosts'])} Hosts und "
        f"{len(findings)} Sicherheitsbefunde identifiziert. Das Gesamtrisiko wird als "
        f"{_SEVERITY_DE.get(label, label)} eingestuft. Es wurden {counts['CRITICAL']} kritische, "
        f"{counts['HIGH']} hohe und {counts['MEDIUM']} mittlere Befunde identifiziert.",
    )
    pdf.section_heading("Wichtige Erkenntnisse")
    top_findings = sorted(findings, key=lambda f: _severity_rank(str(f.get("severity", "INFO"))))[:8]
    if top_findings:
        for finding in top_findings:
            pdf.paragraph(f"• {_clip(finding.get('title'))}", size=19, leading=28)
    else:
        pdf.paragraph("• Keine sicherheitsrelevanten Befunde extrahiert.", size=19, leading=28)
    pdf.y += 12
    pdf.text(pdf.M, pdf.y, "Geprüfte Kategorien", _font(20, bold=True), _PDF_COLORS["blue"])
    pdf.y += 36
    pdf.category_grid(ctx["categories"][:8])

    # Risk overview
    pdf.new_page("2. Risikoübersicht")
    pdf.title("2. Risikoübersicht")
    x, y = pdf.M, pdf.y
    tile_h = 185
    total_w = pdf.content_w
    first_w = 235
    sev_w = (total_w - first_w) // 5
    risk_color = _PDF_COLORS.get(label, _PDF_COLORS["INFO"])
    pdf.draw.rectangle((x, y, x + first_w, y + tile_h), fill=risk_color)
    risk_label = _SEVERITY_DE.get(label, label)
    risk_lines = ["KRITIS", "CH"] if risk_label == "KRITISCH" else [risk_label]
    yy = y + (48 if len(risk_lines) == 1 else 38)
    for line in risk_lines:
        pdf.text(x + first_w // 2, yy, line, _font(43, bold=True), _PDF_COLORS["white"], anchor="mm")
        yy += 48
    pdf.text(x + first_w // 2, y + 142, f"{risk_label}ES RISIKO", _font(15), _PDF_COLORS["white"], anchor="mm")
    xx = x + first_w
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        pdf.draw.rectangle((xx, y + 40, xx + sev_w, y + tile_h - 38), fill=_PDF_COLORS[sev])
        pdf.text(xx + sev_w // 2, y + 76, str(counts[sev]), _font(42, bold=True), _PDF_COLORS["white"], anchor="mm")
        pdf.text(xx + sev_w // 2, y + 126, _SEVERITY_DE[sev], _font(15), _PDF_COLORS["white"], anchor="mm")
        xx += sev_w
    pdf.draw.rectangle((x, y, x + total_w, y + tile_h + 62), outline=_PDF_COLORS["line"], width=1)
    pdf.text(x + 24, y + tile_h + 22, f"Gesamtzahl der Befunde: {len(findings)}", _font(18), _PDF_COLORS["muted"])
    pdf.y += tile_h + 92
    pdf.section_heading("Risikobewertung nach Kategorien")
    grouped: dict[str, list[dict]] = defaultdict(list)
    for finding in findings:
        grouped[_CATEGORY_DE.get(str(finding.get("category", "")), str(finding.get("category", "")) or "Allgemein")].append(finding)
    rows = []
    for category, items in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        highest = sorted(items, key=lambda f: _severity_rank(str(f.get("severity", "INFO"))))[0].get("severity", "INFO")
        rows.append([category, str(len(items)), _SEVERITY_DE.get(str(highest), str(highest))])
    pdf.simple_table(["Kategorie", "Anzahl", "Höchstes Risiko"], rows or [["Keine Befunde", "0", "INFO"]], [520, 170, 314])

    # Attack surface
    pdf.new_page("3. Angriffsoberfläche")
    pdf.title("3. Angriffsoberfläche")
    pdf.section_heading(f"3.1 Entdeckte Subdomains ({len(ctx['subdomains'])})")
    pdf.category_grid([_clip(s) for s in ctx["subdomains"][:24]])
    pdf.section_heading(f"3.2 Hosts ({len(ctx['hosts'])})")
    host_rows = []
    for host in ctx["hosts"][:18]:
        host_rows.append([
            _clip(host.get("hostname")),
            _clip(host.get("ip")),
            ", ".join(host.get("roles", []) or []) or "-",
        ])
    pdf.simple_table(["Hostname", "IP-Adresse", "Rolle"], host_rows, [520, 330, 154])

    # DNS and Mail
    pdf.new_page("4. DNS-Konfiguration")
    pdf.title("4. DNS-Konfiguration")
    dns = results.get("dns_configuration", {}) or {}
    op = dns.get("operative_security", {}) or {}
    admin = dns.get("administrative_security", {}) or {}
    whois = admin.get("whois_protection", {}) or {}
    dns_rows = [
        ["Registrar", _clip(whois.get("registrar"))],
        ["Created", _clip(whois.get("creation_date"))],
        ["Expires", _clip(whois.get("expiration_date"))],
        ["DNSSEC", "Aktiv" if (op.get("dnssec", {}) or {}).get("enabled") else "Nicht aktiv"],
        ["CAA Records", "Vorhanden" if (admin.get("caa_records", {}) or {}).get("has_caa") else "Fehlend"],
        ["Zone Transfer", "Vulnerable" if (op.get("zone_transfer", {}) or {}).get("vulnerable_ns") else "Geblockt"],
    ]
    pdf.simple_table(["Prüfpunkt", "Ergebnis"], dns_rows, [330, 674])

    pdf.new_page("5. E-Mail-Konfiguration")
    pdf.title("5. E-Mail-Konfiguration")
    mail = results.get("mail_configuration", {}) or {}
    spf = mail.get("spf", {}) or {}
    dkim = mail.get("dkim", {}) or {}
    dmarc = mail.get("dmarc", {}) or {}
    mail_rows = [
        ["SPF", "Ja" if spf.get("has_spf") else "Nein", _clip(spf.get("all_qualifier"))],
        ["DKIM", "Ja" if dkim.get("has_dkim") else "Nein", f"{len(dkim.get('found_selectors', []) or [])} Selector"],
        ["DMARC", "Ja" if dmarc.get("has_dmarc") else "Nein", _clip(dmarc.get("policy"))],
        ["Diversifizierung", "Niedrig", "nur 1 MX-Server – kein Backup" if len(mail.get("mx_records", []) or []) <= 1 else "Mehrere MX-Server"],
    ]
    pdf.simple_table(["Prüfpunkt", "Status", "Details"], mail_rows, [300, 190, 514])

    # Web
    pdf.new_page("6. Web-Sicherheit & Datenschutz")
    pdf.title("6. Web-Sicherheit & Datenschutz")
    pr = results.get("privacy_reputation", {}) or {}
    cert = (pr.get("web_tls", {}) or {}).get("certificate", {}) or {}
    sec = pr.get("security_headers", {}) or {}
    web_rows = [
        ["TLS Subject", _clip((cert.get("subject") or {}).get("commonName"))],
        ["Issuer", _clip((cert.get("issuer") or {}).get("organizationName"))],
        ["Gültigkeit", f"{_clip(cert.get('days_until_expiry'))} Tage"],
        ["Fehlende Security Header", ", ".join(sec.get("headers_missing", []) or []) or "Keine"],
    ]
    pdf.simple_table(["Prüfpunkt", "Ergebnis"], web_rows, [330, 674])

    # Findings
    pdf.new_page("7. Alle Ergebnisse")
    pdf.title("7. Alle Ergebnisse")
    sorted_findings = sorted(findings, key=lambda f: (_severity_rank(str(f.get("severity", "INFO"))), _clip(f.get("title"))))
    if sorted_findings:
        for finding in sorted_findings[:80]:
            pdf.finding_card(finding)
    else:
        pdf.info_box("Keine Befunde", "Aus den ausgewählten Scan-Modulen wurden keine Sicherheitsbefunde extrahiert.")

    # Recommendations
    pdf.new_page("8. Handlungsempfehlungen")
    pdf.title("8. Handlungsempfehlungen")
    recommendations = [
        "Kritische und hohe Befunde priorisiert beheben und nach der Änderung einen erneuten Scan durchführen.",
        "Öffentlich erreichbare Admin-, Datenbank-, Mail- und Legacy-Dienste inventarisieren und auf VPN/IP-Allowlisting begrenzen.",
        "DNSSEC, CAA, SPF, DKIM und DMARC auf eine harte Policy bringen und regelmäßig überwachen.",
        "Security Header konsistent ausrollen: HSTS, CSP, X-Frame-Options, Referrer-Policy und sichere Cookie-Flags.",
        "Subdomains ohne aktiven Zweck entfernen oder übernehmen, um Takeover-Risiken zu vermeiden.",
        "Report-Artefakte und JSON-Rohdaten versionieren, damit Risikoänderungen über Zeit sichtbar bleiben.",
    ]
    for item in recommendations:
        pdf.paragraph(f"• {item}", size=21, leading=32)

    pdf.save(path)


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
        """Generate a styled A4 PDF report matching the linked.it assessment layout."""
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
        try:
            _generate_styled_pdf(filepath, self.domain, self.results, self.timestamp)
        except Exception as exc:
            log.warning(f"Styled PDF failed, falling back to simple PDF: {exc}")
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
