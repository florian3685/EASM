const C = window.CyberScan;

let apiKeys = [];

function renderApiKeyEditor() {
  if (!apiKeys.length) {
    C.$("apiKeyEditor").innerHTML = `<div class="empty">No API key definitions found.</div>`;
    return;
  }

  C.$("apiKeyEditor").innerHTML = `<div class="key-list">${apiKeys.map((key) => `
    <div class="key-row">
      <div>
        <h3>${C.escapeHtml(key.label)}</h3>
        <p>${C.escapeHtml(key.description)}</p>
        <code>${C.escapeHtml(key.env)}${key.masked ? ` · ${C.escapeHtml(key.masked)}` : ""}</code>
      </div>
      <div class="key-controls">
        <input data-api-key="${C.escapeHtml(key.env)}" type="password" placeholder="${key.configured ? "leave blank to keep current key" : "paste API key"}" autocomplete="off">
        <label class="key-clear">
          <input data-api-clear="${C.escapeHtml(key.env)}" type="checkbox">
          Clear saved value
        </label>
      </div>
      <span class="key-status ${key.configured ? "on" : ""}">${key.configured ? "configured" : "missing"}</span>
    </div>
  `).join("")}</div>`;
}

async function loadApiKeys() {
  const data = await C.api("/api/bootstrap");
  C.updateShell(data);
  if (!data.is_admin) {
    location.href = "/dashboard";
    return;
  }
  apiKeys = data.api_key_status || [];
  renderApiKeyEditor();
  C.mountIcons();
}

async function saveApiKeys() {
  C.setNotice("apiKeyNotice", "");
  const values = {};
  const clear = [];
  document.querySelectorAll("[data-api-key]").forEach((node) => {
    const value = node.value.trim();
    if (value) values[node.dataset.apiKey] = value;
  });
  document.querySelectorAll("[data-api-clear]:checked").forEach((node) => {
    clear.push(node.dataset.apiClear);
  });

  if (!Object.keys(values).length && !clear.length) {
    C.setNotice("apiKeyNotice", "No API key changes to save.");
    return;
  }

  C.$("saveApiKeys").disabled = true;
  try {
    const data = await C.api("/api/admin/api-keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ values, clear })
    });
    apiKeys = data.api_keys || [];
    renderApiKeyEditor();
    C.setNotice("apiKeyNotice", "API keys saved.");
    C.mountIcons();
  } catch (error) {
    C.setNotice("apiKeyNotice", error.message);
  } finally {
    C.$("saveApiKeys").disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  C.initShell();
  C.$("saveApiKeys").addEventListener("click", saveApiKeys);
  loadApiKeys();
});
