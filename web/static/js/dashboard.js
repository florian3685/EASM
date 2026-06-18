const C = window.CyberScan;

function formatDay(value) {
  if (!value) return "-";
  const date = new Date(`${String(value).slice(0, 10)}T00:00:00`);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString();
}

function dueLabel(item) {
  if (!item?.active) return "Paused";
  if (item.active_job_status) return `${item.active_job_status} now`;
  if (item.due_state === "overdue") return `${Math.abs(Number(item.days_until || 0))}d overdue`;
  if (item.due_state === "due_today") return "Due today";
  if (item.due_state === "due_soon") return `Due in ${Number(item.days_until || 0)}d`;
  return `Due ${formatDay(item.next_scan)}`;
}

function renderMetrics(jobs, reports, overview, maxWorkers) {
  const pdfs = (reports || []).filter((report) => report.type === "pdf").length;
  const critical = (reports || []).filter((report) => report.risk_label === "CRITICAL").length;
  const failed = (jobs || []).filter((job) => job.status === "failed").length;

  C.$("metrics").innerHTML = [
    { label: "Active", value: overview.running || 0, hint: `${maxWorkers || 1} worker slot(s)`, icon: "activity" },
    { label: "Due Now", value: overview.due_now || 0, hint: `${overview.overdue || 0} overdue`, icon: "alarm-clock" },
    { label: "Need Scan", value: overview.needs_scan || 0, hint: "Not queued yet", icon: "scan-search" },
    { label: "This Week", value: overview.due_this_week || 0, hint: "Scheduled next 7 days", icon: "calendar-days" },
    { label: "Reports", value: reports?.length || 0, hint: `${pdfs} customer PDFs`, icon: "file-text" },
    { label: "Critical", value: critical, hint: failed ? `${failed} failed scan(s)` : "Highest risk reports", icon: "triangle-alert" }
  ].map((item) => `
    <article class="metric">
      <div class="metric-icon">${C.icon(item.icon)}</div>
      <div class="metric-label">${C.escapeHtml(item.label)}</div>
      <div class="metric-value" data-count="${C.escapeHtml(item.value)}">0</div>
      <div class="metric-hint">${C.escapeHtml(item.hint)}</div>
    </article>
  `).join("");
  C.animateNumbers(C.$("metrics"));
}

function renderDashboard(jobs, reports, schedule, overview) {
  const latestJob = (jobs || [])[0];
  const latestPdfs = (reports || []).filter((report) => report.type === "pdf").slice(0, 6);
  const latestReports = (reports || []).slice(0, 5);
  const plannerItems = (schedule || [])
    .filter((item) => item.active || item.needs_scan || item.due_state === "overdue")
    .slice(0, 6);

  const latestScanHtml = latestJob ? `
    <div class="overview-main">${C.escapeHtml(latestJob.domain)}</div>
    <div class="overview-meta">${C.escapeHtml(latestJob.status)} · ${C.escapeHtml(latestJob.phase || "No phase")} · by ${C.escapeHtml(latestJob.created_by || "-")}</div>
    <div class="chip-row">
      <span class="chip">${C.escapeHtml((latestJob.modules || []).length)} module(s)</span>
      <span class="chip ${latestJob.authorized ? "ok" : "danger"}">${latestJob.authorized ? "authorized" : "authorization missing"}</span>
      ${latestJob.generated_files?.length ? `<span class="chip ok">${latestJob.generated_files.length} file(s)</span>` : ""}
    </div>
  ` : `<div class="empty">No scan jobs yet.</div>`;

  const plannerHtml = plannerItems.length ? plannerItems.map((item) => `
    <div class="compact-row">
      <div>
        <strong>${C.escapeHtml(item.domain)}</strong>
        <span>${C.escapeHtml(item.profile_name || item.profile || "-")} · every ${C.escapeHtml(item.cadence_days)}d · ${C.escapeHtml(dueLabel(item))}</span>
      </div>
      <span class="due-state ${C.escapeHtml(item.due_state)}">${C.escapeHtml(item.needs_scan ? "Needs scan" : item.due_state.replace("_", " "))}</span>
    </div>
  `).join("") : `<div class="empty">No schedules yet.</div>`;

  const pdfRows = latestPdfs.length ? latestPdfs.map((report) => `
    <div class="compact-row">
      <div>
        <strong>${C.escapeHtml(report.domain)}</strong>
        <span>${C.escapeHtml(report.file)} · ${C.escapeHtml(C.formatDate(report.modified))}</span>
      </div>
      ${C.reportLinkActions(report.url, "PDF", report.download_url)}
    </div>
  `).join("") : `<div class="empty">No PDFs generated yet.</div>`;

  const reportRows = latestReports.length ? latestReports.map((report) => `
    <div class="compact-row">
      <div>
        <strong>${C.escapeHtml(report.domain)}</strong>
        <span>${C.escapeHtml(report.type.toUpperCase())} · risk ${C.escapeHtml(report.risk_label || "-")} · ${C.escapeHtml(C.formatDate(report.modified))}</span>
      </div>
      ${C.reportLinkActions(report.url, C.reportActionLabel(report.url), report.download_url)}
    </div>
  `).join("") : `<div class="empty">No reports found.</div>`;

  C.$("dashboardContent").innerHTML = `
    <div class="grid dashboard-grid">
      <div class="overview-block">
        <h3>Latest Scan</h3>
        ${latestScanHtml}
      </div>
      <div class="overview-block">
        <div class="block-title-row">
          <h3>Scan Planner</h3>
          <a class="secondary" href="/scans#schedule">${C.icon("calendar-clock")}Planner</a>
        </div>
        <div class="overview-main">${C.escapeHtml(overview.needs_scan || 0)}</div>
        <div class="overview-meta">${C.escapeHtml(overview.scheduled_active || 0)} active schedule(s), ${C.escapeHtml(overview.never_scanned || 0)} never scanned</div>
        <div class="compact-list">${plannerHtml}</div>
      </div>
      <div class="overview-block">
        <h3>Latest PDFs</h3>
        <div class="compact-list">${pdfRows}</div>
      </div>
      <div class="overview-block">
        <h3>Latest Report Files</h3>
        <div class="compact-list">${reportRows}</div>
      </div>
    </div>`;
}

async function loadDashboard() {
  const data = await C.api("/api/bootstrap");
  const overview = data.scan_overview || {};
  C.updateShell(data);
  renderMetrics(data.jobs, data.reports, overview, data.max_workers);
  renderDashboard(data.jobs, data.reports, data.schedule || [], overview);
  C.mountIcons();
}

document.addEventListener("DOMContentLoaded", () => {
  C.initShell();
  loadDashboard();
  setInterval(loadDashboard, 5000);
});
