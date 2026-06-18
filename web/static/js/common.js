(function () {
  const routes = {
    dashboard: "/dashboard",
    scans: "/scans",
    reports: "/reports",
    "admin-users": "/admin/users",
    "admin-api-keys": "/admin/api-keys"
  };

  function $(id) {
    return document.getElementById(id);
  }

  function icon(name) {
    return `<i data-lucide="${name}"></i>`;
  }

  function mountIcons() {
    if (window.lucide) window.lucide.createIcons();
  }

  function debounce(fn, delay = 160) {
    let timer = null;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    }[char]));
  }

  function formatDate(value) {
    if (!value) return "-";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
  }

  function setNotice(id, message) {
    const node = $(id);
    if (!node) return;
    node.textContent = message || "";
    node.classList.toggle("show", Boolean(message));
  }

  async function api(path, options) {
    const response = await fetch(path, { cache: "no-store", ...(options || {}) });
    if (response.status === 401) {
      location.href = "/login";
      throw new Error("Authentication required.");
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Request failed.");
    return data;
  }

  function themeIcon(theme) {
    return theme === "dark" ? "sun" : "moon";
  }

  function applyTheme(theme) {
    const chosen = theme === "dark" ? "dark" : "light";
    document.documentElement.dataset.theme = chosen;
    localStorage.setItem("cyberscan-theme", chosen);
    document.querySelectorAll("[data-theme-toggle]").forEach((node) => {
      node.innerHTML = icon(themeIcon(chosen));
      node.setAttribute("aria-label", chosen === "dark" ? "Switch to light mode" : "Switch to dark mode");
      node.title = chosen === "dark" ? "Light mode" : "Dark mode";
    });
    mountIcons();
  }

  function initTheme() {
    const stored = localStorage.getItem("cyberscan-theme");
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(stored || (prefersDark ? "dark" : "light"));
    document.querySelectorAll("[data-theme-toggle]").forEach((node) => {
      node.addEventListener("click", () => {
        const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
        applyTheme(next);
      });
    });
  }

  function updateShell(data) {
    window.CyberScanState = data || {};
    const page = document.body.dataset.page;
    document.querySelectorAll("[data-route-link]").forEach((node) => {
      const adminOnly = node.dataset.adminOnly === "true";
      node.style.display = adminOnly && !data.is_admin ? "none" : "inline-flex";
      node.classList.toggle("active", node.dataset.routeLink === page);
    });

    const userLabel = $("userLabel");
    if (userLabel) userLabel.textContent = `${data.user || "local"} (${data.user_role || "viewer"})`;

    const logout = document.querySelector(".logout");
    if (logout) logout.style.display = data.auth_mode === "open" ? "none" : "inline-flex";
    renderCommandItems();
  }

  function initShell() {
    initTheme();
    initAmbient();
    initCommandPalette();
    document.body.classList.add("ready");
    mountIcons();
  }

  function animateNumber(node, endValue) {
    const end = Number(endValue || 0);
    if (!Number.isFinite(end)) {
      node.textContent = endValue;
      return;
    }
    const start = Number(node.dataset.current || 0);
    const duration = 520;
    const started = performance.now();
    function tick(now) {
      const progress = Math.min(1, (now - started) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      const value = Math.round(start + (end - start) * eased);
      node.textContent = String(value);
      if (progress < 1) requestAnimationFrame(tick);
      else node.dataset.current = String(end);
    }
    requestAnimationFrame(tick);
  }

  function animateNumbers(root = document) {
    root.querySelectorAll("[data-count]").forEach((node) => animateNumber(node, node.dataset.count));
  }

  function initAmbient() {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (document.querySelector(".ambient-canvas")) return;

    const canvas = document.createElement("canvas");
    canvas.className = "ambient-canvas";
    canvas.setAttribute("aria-hidden", "true");
    const shell = document.querySelector(".app-shell") || document.body;
    shell.prepend(canvas);

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let dpr = 1;
    const nodes = Array.from({ length: 28 }, (_, index) => ({
      x: Math.random(),
      y: Math.random(),
      speed: .05 + Math.random() * .08,
      phase: index * .37
    }));

    function resize() {
      dpr = Math.min(2, window.devicePixelRatio || 1);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    function draw(now) {
      const theme = document.documentElement.dataset.theme || "light";
      const stroke = theme === "dark" ? "rgba(0, 166, 232, .28)" : "rgba(0, 119, 182, .20)";
      const dot = theme === "dark" ? "rgba(67, 199, 255, .52)" : "rgba(0, 119, 182, .34)";
      ctx.clearRect(0, 0, width, height);
      ctx.lineWidth = 1;

      const points = nodes.map((node) => {
        const x = node.x * width + Math.sin(now / 1600 + node.phase) * 18;
        const y = ((node.y + now * node.speed / 80000) % 1) * height;
        return { x, y };
      });

      for (let i = 0; i < points.length; i += 1) {
        for (let j = i + 1; j < points.length; j += 1) {
          const dx = points[i].x - points[j].x;
          const dy = points[i].y - points[j].y;
          const dist = Math.hypot(dx, dy);
          if (dist < 175) {
            ctx.globalAlpha = 1 - dist / 175;
            ctx.strokeStyle = stroke;
            ctx.beginPath();
            ctx.moveTo(points[i].x, points[i].y);
            ctx.lineTo(points[j].x, points[j].y);
            ctx.stroke();
          }
        }
      }

      ctx.globalAlpha = 1;
      points.forEach((point, index) => {
        const pulse = 2.2 + Math.sin(now / 500 + index) * .8;
        ctx.fillStyle = dot;
        ctx.beginPath();
        ctx.arc(point.x, point.y, pulse, 0, Math.PI * 2);
        ctx.fill();
      });

      const scanY = (now / 28) % (height + 160) - 80;
      const gradient = ctx.createLinearGradient(0, scanY - 70, 0, scanY + 70);
      gradient.addColorStop(0, "rgba(0, 166, 232, 0)");
      gradient.addColorStop(.5, theme === "dark" ? "rgba(0, 166, 232, .12)" : "rgba(0, 119, 182, .08)");
      gradient.addColorStop(1, "rgba(0, 166, 232, 0)");
      ctx.fillStyle = gradient;
      ctx.fillRect(0, scanY - 70, width, 140);

      requestAnimationFrame(draw);
    }

    resize();
    window.addEventListener("resize", resize);
    requestAnimationFrame(draw);
  }

  function commandDefinitions() {
    const state = window.CyberScanState || {};
    const items = [
      { id: "dashboard", label: "Dashboard", hint: "Open command center", icon: "layout-dashboard", href: "/dashboard" },
      { id: "scans", label: "New scan", hint: "Launch and monitor scans", icon: "radar", href: "/scans" },
      { id: "planner", label: "Scan planner", hint: "Schedule recurring customer scans", icon: "calendar-clock", href: "/scans#schedule" },
      { id: "reports", label: "Reports", hint: "Open generated evidence", icon: "file-text", href: "/reports" },
      { id: "theme", label: "Toggle theme", hint: "Switch dark and white mode", icon: "sparkles", action: () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark") }
    ];
    if (state.is_admin) {
      items.push(
        { id: "users", label: "Users", hint: "Manage team access", icon: "users", href: "/admin/users" },
        { id: "keys", label: "API keys", hint: "Manage enrichment credentials", icon: "key-round", href: "/admin/api-keys" }
      );
    }
    return items;
  }

  function ensureCommandPalette() {
    let palette = document.querySelector("[data-command-palette]");
    if (palette) return palette;
    palette = document.createElement("div");
    palette.className = "command-palette";
    palette.dataset.commandPalette = "true";
    palette.innerHTML = `
      <div class="command-box" role="dialog" aria-modal="true" aria-label="Command palette">
        <div class="command-search">
          ${icon("search")}
          <input id="commandInput" type="search" placeholder="Jump to page or action..." autocomplete="off">
          <span class="kbd">ESC</span>
        </div>
        <div id="commandList" class="command-list"></div>
      </div>`;
    document.body.appendChild(palette);
    palette.addEventListener("click", (event) => {
      if (event.target === palette) closeCommandPalette();
    });
    const input = palette.querySelector("#commandInput");
    input.addEventListener("input", renderCommandItems);
    input.addEventListener("keydown", (event) => {
      const items = [...palette.querySelectorAll(".command-item")];
      const current = items.findIndex((item) => item.classList.contains("active"));
      if (event.key === "ArrowDown") {
        event.preventDefault();
        const next = items[(current + 1 + items.length) % items.length];
        items.forEach((item) => item.classList.remove("active"));
        if (next) next.classList.add("active");
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        const next = items[(current - 1 + items.length) % items.length];
        items.forEach((item) => item.classList.remove("active"));
        if (next) next.classList.add("active");
      }
      if (event.key === "Enter") {
        event.preventDefault();
        const active = palette.querySelector(".command-item.active") || items[0];
        if (active) active.click();
      }
    });
    return palette;
  }

  function renderCommandItems() {
    const palette = ensureCommandPalette();
    const input = palette.querySelector("#commandInput");
    const list = palette.querySelector("#commandList");
    const query = (input.value || "").trim().toLowerCase();
    const items = commandDefinitions().filter((item) => {
      const haystack = `${item.label} ${item.hint}`.toLowerCase();
      return !query || haystack.includes(query);
    });
    list.innerHTML = items.length ? items.map((item, index) => `
      <button class="command-item ${index === 0 ? "active" : ""}" type="button" data-command-id="${item.id}">
        <span class="cmd-icon">${icon(item.icon)}</span>
        <span><strong>${escapeHtml(item.label)}</strong><span>${escapeHtml(item.hint)}</span></span>
        ${item.href ? '<span class="kbd">GO</span>' : '<span class="kbd">RUN</span>'}
      </button>
    `).join("") : `<div class="command-empty">No command found.</div>`;
    list.querySelectorAll("[data-command-id]").forEach((node) => {
      node.addEventListener("click", () => {
        const item = commandDefinitions().find((entry) => entry.id === node.dataset.commandId);
        if (!item) return;
        closeCommandPalette();
        if (item.action) item.action();
        if (item.href) location.href = item.href;
      });
    });
    mountIcons();
  }

  function openCommandPalette() {
    const palette = ensureCommandPalette();
    palette.classList.add("open");
    const input = palette.querySelector("#commandInput");
    input.value = "";
    renderCommandItems();
    setTimeout(() => input.focus(), 0);
  }

  function closeCommandPalette() {
    const palette = document.querySelector("[data-command-palette]");
    if (palette) palette.classList.remove("open");
  }

  function initCommandPalette() {
    ensureCommandPalette();
    document.querySelectorAll("[data-command-open]").forEach((node) => {
      node.addEventListener("click", openCommandPalette);
    });
    document.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        openCommandPalette();
      } else if (event.key === "Escape") {
        closeCommandPalette();
      }
    });
  }

  function reportActionLabel(url) {
    if (String(url).endsWith(".html")) return "HTML";
    if (String(url).endsWith(".pdf")) return "PDF";
    return "JSON";
  }

  function downloadUrl(url) {
    const separator = String(url).includes("?") ? "&" : "?";
    return `${url}${separator}download=1`;
  }

  function reportLinkActions(url, label, explicitDownloadUrl) {
    const safeUrl = escapeHtml(url || "#");
    const safeDownloadUrl = escapeHtml(explicitDownloadUrl || downloadUrl(url || "#"));
    const safeLabel = escapeHtml(label || "Open");
    return `<div class="link-actions">
      <a href="${safeUrl}" target="_blank" rel="noreferrer">${icon("external-link")}${safeLabel}</a>
      <a class="download-button" href="${safeDownloadUrl}" download>${icon("download")}Download</a>
    </div>`;
  }

  window.CyberScan = {
    $,
    api,
    icon,
    routes,
    mountIcons,
    debounce,
    animateNumbers,
    escapeHtml,
    formatDate,
    setNotice,
    initTheme,
    initShell,
    updateShell,
    reportActionLabel,
    reportLinkActions,
    openCommandPalette
  };
})();
