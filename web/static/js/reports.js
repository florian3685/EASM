const C = window.CyberScan;
let allReports = [];

function filteredReports() {
  const query = (C.$("reportSearch")?.value || "").trim().toLowerCase();
  const risk = C.$("riskFilter")?.value || "";
  return allReports.filter((report) => {
    const haystack = `${report.domain || ""} ${report.file || ""} ${report.type || ""}`.toLowerCase();
    const matchesQuery = !query || haystack.includes(query);
    const matchesRisk = !risk || report.risk_label === risk;
    return matchesQuery && matchesRisk;
  });
}

function renderReports(reports = filteredReports()) {
  if (!reports || !reports.length) {
    C.$("reports").innerHTML = `<div class="empty">No reports found.</div>`;
    return;
  }

  const rows = reports.map((report) => {
    const risk = report.risk_label || "-";
    const when = C.formatDate(report.scan_date || report.modified);
    const action = report.type === "html" ? "HTML" : report.type === "pdf" ? "PDF" : "JSON";
    return `<tr>
      <td><strong>${C.escapeHtml(report.domain)}</strong><br><span class="job-meta">${C.escapeHtml(report.file)}</span></td>
      <td><span class="risk ${C.escapeHtml(risk)}">${C.escapeHtml(risk)}</span></td>
      <td>${C.escapeHtml(report.findings ?? "-")}</td>
      <td>${C.escapeHtml(when)}</td>
      <td>${C.reportLinkActions(report.url, action, report.download_url)}</td>
    </tr>`;
  }).join("");

  C.$("reports").innerHTML = `<div class="table-wrap">
    <table>
      <thead><tr><th>Target</th><th>Risk</th><th>Findings</th><th>Date</th><th>Actions</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

async function loadReports() {
  const data = await C.api("/api/bootstrap");
  C.updateShell(data);
  allReports = data.reports || [];
  renderReports();
  C.mountIcons();
}

document.addEventListener("DOMContentLoaded", () => {
  C.initShell();
  C.$("reportSearch").addEventListener("input", C.debounce(() => renderReports(), 120));
  C.$("riskFilter").addEventListener("change", () => renderReports());
  loadReports();
  setInterval(loadReports, 10000);
});
