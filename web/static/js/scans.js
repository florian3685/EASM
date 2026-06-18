const C = window.CyberScan;

const state = {
  modules: [],
  profiles: [],
  selectedProfile: "full_recon",
  canScan: false,
  jobs: [],
  schedule: [],
  overview: {},
  scrolledToSchedule: false
};

function selectedModules() {
  return [...document.querySelectorAll("[data-module]:checked")].map((node) => Number(node.value));
}

function setModules(modules) {
  const selected = new Set(modules);
  document.querySelectorAll("[data-module]").forEach((node) => {
    node.checked = selected.has(Number(node.value));
  });
}

function profileById(profileId) {
  return state.profiles.find((profile) => profile.id === profileId) || state.profiles[0];
}

function todayInputValue() {
  return new Date().toISOString().slice(0, 10);
}

function formatDay(value) {
  if (!value) return "-";
  const date = new Date(`${String(value).slice(0, 10)}T00:00:00`);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString();
}

function dueLabel(item) {
  if (!item.active) return "Paused";
  if (item.active_job_status) return `${item.active_job_status} job active`;
  if (item.due_state === "overdue") return `${Math.abs(Number(item.days_until || 0))}d overdue`;
  if (item.due_state === "due_today") return "Due today";
  if (item.due_state === "due_soon") return `Due in ${Number(item.days_until || 0)}d`;
  return `Due ${formatDay(item.next_scan)}`;
}

function renderProfiles() {
  C.$("profiles").innerHTML = state.profiles.map((profile) => `
    <button type="button" class="profile-btn ${profile.id === state.selectedProfile ? "active" : ""}" data-profile="${profile.id}">
      ${C.escapeHtml(profile.name)}
    </button>
  `).join("");

  document.querySelectorAll("[data-profile]").forEach((node) => {
    node.addEventListener("click", () => {
      const profile = profileById(node.dataset.profile);
      if (!profile) return;
      state.selectedProfile = profile.id;
      setModules(profile.modules);
      C.$("exploit").checked = Boolean(profile.exploit);
      renderProfiles();
    });
  });
}

function renderScheduleProfiles() {
  const select = C.$("scheduleProfile");
  if (!select) return;
  select.innerHTML = state.profiles.map((profile) => `
    <option value="${C.escapeHtml(profile.id)}">${C.escapeHtml(profile.name)}</option>
  `).join("");
  select.value = "full_recon";
}

function renderModules() {
  C.$("modules").innerHTML = state.modules.map((module) => `
    <label class="module ${module.danger ? "danger" : ""}">
      <input data-module type="checkbox" value="${module.id}" ${module.default ? "checked" : ""}>
      <span>
        <span class="module-title">${module.id}. ${C.escapeHtml(module.name)}</span>
        <span class="module-desc">${C.escapeHtml(module.description)}</span>
      </span>
    </label>
  `).join("");
}

function renderPermissions(canScan) {
  state.canScan = Boolean(canScan);
  C.$("startScan").disabled = !state.canScan;
  C.$("startScan").innerHTML = state.canScan
    ? `${C.icon("play")}<span>Start customer scan</span>`
    : `${C.icon("lock")}<span>Scanner role required</span>`;
  const saveSchedule = C.$("saveSchedule");
  if (saveSchedule) saveSchedule.disabled = !state.canScan;
}

function filteredJobs() {
  const query = (C.$("jobSearch")?.value || "").trim().toLowerCase();
  if (!query) return state.jobs;
  return state.jobs.filter((job) => {
    const haystack = `${job.domain || ""} ${job.status || ""} ${job.phase || ""} ${(job.modules || []).join(" ")}`.toLowerCase();
    return haystack.includes(query);
  });
}

function renderJobs(jobs = filteredJobs()) {
  if (!jobs || !jobs.length) {
    C.$("jobs").innerHTML = `<div class="empty">No scans yet.</div>`;
    return;
  }

  C.$("jobs").innerHTML = jobs.map((job) => {
    const links = (job.generated_files || []).map((url) => C.reportLinkActions(url, C.reportActionLabel(url))).join(" ");
    const logs = (job.logs || []).slice(-18).map(C.escapeHtml).join("\n");
    const chips = [
      `<span class="chip">by ${C.escapeHtml(job.created_by || "local")}</span>`,
      `<span class="chip ${job.stealth ? "ok" : ""}">jitter ${job.stealth ? "on" : "off"}</span>`,
      job.exploit ? `<span class="chip danger">exploit on</span>` : `<span class="chip">safe</span>`,
      job.fresh ? `<span class="chip">fresh</span>` : "",
      job.authorized ? `<span class="chip ok">authorized</span>` : `<span class="chip danger">no auth</span>`
    ].filter(Boolean).join("");

    return `<article class="job">
      <div class="job-main">
        <div>
          <h3>${C.escapeHtml(job.domain)}</h3>
          <div class="job-meta">${C.escapeHtml(job.phase || "")} · modules ${C.escapeHtml((job.modules || []).join(", "))}</div>
          <div class="chip-row">${chips}</div>
          ${job.error ? `<div class="job-meta" style="color: var(--danger); font-weight: 850">${C.escapeHtml(job.error)}</div>` : ""}
          ${links ? `<div class="report-actions-list">${links}</div>` : ""}
        </div>
        <span class="status ${C.escapeHtml(job.status)}">${C.escapeHtml(job.status)}</span>
      </div>
      <div class="progress"><span style="width:${Number(job.progress || 0)}%"></span></div>
      <pre class="logs">${logs}</pre>
    </article>`;
  }).join("");
}

function renderScheduleStats() {
  const overview = state.overview || {};
  C.$("scheduleStats").innerHTML = [
    ["Need scan", overview.needs_scan || 0],
    ["Due now", overview.due_now || 0],
    ["This week", overview.due_this_week || 0],
    ["Planned", overview.scheduled_active || 0]
  ].map(([label, value]) => `
    <div class="mini-metric">
      <span>${C.escapeHtml(label)}</span>
      <strong data-count="${C.escapeHtml(value)}">0</strong>
    </div>
  `).join("");
  C.animateNumbers(C.$("scheduleStats"));
}

function renderScheduleList() {
  const schedule = state.schedule || [];
  if (!schedule.length) {
    C.$("scheduleList").innerHTML = `<div class="empty">No scheduled scans yet.</div>`;
    return;
  }

  C.$("scheduleList").innerHTML = schedule.map((item) => {
    const chips = [
      `<span class="chip">${C.escapeHtml(item.profile_name || item.profile || "-")}</span>`,
      `<span class="chip">every ${C.escapeHtml(item.cadence_days)}d</span>`,
      item.last_scan_date ? `<span class="chip ok">last ${C.escapeHtml(C.formatDate(item.last_scan_date))}</span>` : `<span class="chip danger">never scanned</span>`,
      item.last_queued_at ? `<span class="chip">queued ${C.escapeHtml(C.formatDate(item.last_queued_at))}</span>` : "",
      item.authorized ? `<span class="chip ok">authorized</span>` : `<span class="chip danger">no auth</span>`
    ].filter(Boolean).join("");

    return `<article class="schedule-card">
      <div class="schedule-card-head">
        <div>
          <h3 class="schedule-title">${C.escapeHtml(item.domain)}</h3>
          <div class="schedule-meta">${C.escapeHtml(dueLabel(item))} · next ${C.escapeHtml(formatDay(item.next_scan))}</div>
          <div class="chip-row">${chips}</div>
        </div>
        <span class="due-state ${C.escapeHtml(item.due_state)}">${C.escapeHtml(item.needs_scan ? "Needs scan" : item.due_state.replace("_", " "))}</span>
      </div>
      <div class="actions">
        <button class="secondary" type="button" data-run-schedule="${C.escapeHtml(item.id)}" ${state.canScan ? "" : "disabled"}>${C.icon("play")}<span>Run now</span></button>
        <button class="secondary" type="button" data-delete-schedule="${C.escapeHtml(item.id)}" ${state.canScan ? "" : "disabled"}>${C.icon("trash-2")}<span>Delete</span></button>
      </div>
    </article>`;
  }).join("");

  document.querySelectorAll("[data-run-schedule]").forEach((node) => {
    node.addEventListener("click", () => runSchedule(node.dataset.runSchedule));
  });
  document.querySelectorAll("[data-delete-schedule]").forEach((node) => {
    node.addEventListener("click", () => deleteSchedule(node.dataset.deleteSchedule));
  });
}

function renderSchedule() {
  renderScheduleStats();
  renderScheduleList();
}

async function loadScans() {
  const data = await C.api("/api/bootstrap");
  C.updateShell(data);
  if (!state.modules.length) {
    state.modules = data.modules || [];
    state.profiles = data.profiles || [];
    renderModules();
    renderProfiles();
    renderScheduleProfiles();
    C.$("scheduleNext").value = todayInputValue();
  }
  renderPermissions(data.can_scan);
  state.jobs = data.jobs || [];
  state.schedule = data.schedule || [];
  state.overview = data.scan_overview || {};
  renderJobs();
  renderSchedule();
  C.mountIcons();

  if (location.hash === "#schedule" && !state.scrolledToSchedule) {
    state.scrolledToSchedule = true;
    setTimeout(() => C.$("schedule")?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
  }
}

async function startScan() {
  C.setNotice("notice", "");
  if (!state.canScan) {
    C.setNotice("notice", "Your user role cannot start scans.");
    return;
  }

  const modules = selectedModules();
  const payload = {
    domain: C.$("domain").value.trim(),
    modules,
    stealth: C.$("stealth").checked,
    exploit: C.$("exploit").checked,
    fresh: C.$("fresh").checked,
    authorized: C.$("authorized").checked
  };

  if (!payload.authorized) {
    C.setNotice("notice", "Confirm customer authorization before starting the scan.");
    return;
  }
  if (modules.includes(11) && !payload.exploit) {
    C.setNotice("notice", "Module 11 needs exploit mode.");
    return;
  }

  C.$("startScan").disabled = true;
  try {
    await C.api("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    C.$("domain").value = "";
    C.$("authorized").checked = false;
    await loadScans();
  } catch (error) {
    C.setNotice("notice", error.message);
  } finally {
    C.$("startScan").disabled = !state.canScan;
  }
}

async function saveSchedule(event) {
  event.preventDefault();
  C.setNotice("scheduleNotice", "");
  if (!state.canScan) {
    C.setNotice("scheduleNotice", "Your user role cannot schedule scans.");
    return;
  }

  const profile = profileById(C.$("scheduleProfile").value);
  const payload = {
    domain: C.$("scheduleDomain").value.trim(),
    profile: profile.id,
    modules: profile.modules,
    exploit: Boolean(profile.exploit),
    cadence_days: Number(C.$("scheduleCadence").value || 30),
    next_scan: C.$("scheduleNext").value || todayInputValue(),
    active: C.$("scheduleActive").checked,
    authorized: C.$("scheduleAuthorized").checked,
    stealth: true,
    fresh: true
  };

  if (payload.active && !payload.authorized) {
    C.setNotice("scheduleNotice", "Confirm customer authorization before saving an active schedule.");
    return;
  }

  C.$("saveSchedule").disabled = true;
  try {
    const data = await C.api("/api/schedule", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    state.schedule = data.schedule || [];
    state.overview = data.overview || {};
    C.$("scheduleDomain").value = "";
    C.$("scheduleAuthorized").checked = false;
    renderSchedule();
  } catch (error) {
    C.setNotice("scheduleNotice", error.message);
  } finally {
    C.$("saveSchedule").disabled = !state.canScan;
    C.mountIcons();
  }
}

async function runSchedule(scheduleId) {
  if (!scheduleId) return;
  try {
    const data = await C.api(`/api/schedule/${encodeURIComponent(scheduleId)}/run`, { method: "POST" });
    state.schedule = data.schedule || state.schedule;
    state.overview = data.overview || state.overview;
    await loadScans();
  } catch (error) {
    C.setNotice("scheduleNotice", error.message);
  }
}

async function deleteSchedule(scheduleId) {
  if (!scheduleId || !confirm("Delete this scan schedule?")) return;
  try {
    const data = await C.api(`/api/schedule/${encodeURIComponent(scheduleId)}`, { method: "DELETE" });
    state.schedule = data.schedule || [];
    state.overview = data.overview || {};
    renderSchedule();
    C.mountIcons();
  } catch (error) {
    C.setNotice("scheduleNotice", error.message);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  C.initShell();
  C.$("startScan").addEventListener("click", startScan);
  C.$("refresh").addEventListener("click", loadScans);
  C.$("refreshSchedule").addEventListener("click", loadScans);
  C.$("scheduleForm").addEventListener("submit", saveSchedule);
  C.$("jobSearch").addEventListener("input", C.debounce(() => renderJobs(), 120));
  C.$("selectSafe").addEventListener("click", () => {
    const profile = profileById("full_recon");
    if (!profile) return;
    state.selectedProfile = profile.id;
    setModules(profile.modules);
    C.$("exploit").checked = false;
    renderProfiles();
  });
  C.$("exploit").addEventListener("change", () => {
    const module11 = document.querySelector('[data-module][value="11"]');
    if (module11 && C.$("exploit").checked) module11.checked = true;
  });
  loadScans();
  setInterval(loadScans, 5000);
});
