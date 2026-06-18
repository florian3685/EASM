const C = window.CyberScan;

const state = {
  users: [],
  roles: []
};

function renderRoles() {
  C.$("adminRole").innerHTML = state.roles.map((role) => (
    `<option value="${C.escapeHtml(role.id)}">${C.escapeHtml(role.label)}</option>`
  )).join("");
}

function renderUsers() {
  if (!state.users.length) {
    C.$("users").innerHTML = `<div class="empty">No managed users yet.</div>`;
    return;
  }

  const rows = state.users.map((user) => `
    <tr>
      <td><strong>${C.escapeHtml(user.username)}</strong><br><span class="job-meta">${C.escapeHtml(user.source || "local")}</span></td>
      <td><span class="chip ${user.role === "admin" ? "ok" : ""}">${C.escapeHtml(user.role)}</span></td>
      <td>${user.active ? '<span class="chip ok">active</span>' : '<span class="chip danger">disabled</span>'}</td>
      <td>${user.two_factor_enabled ? '<span class="chip ok">2FA on</span>' : '<span class="chip danger">setup required</span>'}</td>
      <td>${C.escapeHtml(C.formatDate(user.updated_at || user.created_at))}</td>
      <td>
        <div class="link-actions">
          <button type="button" data-edit-user="${C.escapeHtml(user.username)}">${C.icon("pencil")}Edit</button>
          <button type="button" data-reset-2fa="${C.escapeHtml(user.username)}">${C.icon("shield-alert")}Reset 2FA</button>
          <button type="button" data-delete-user="${C.escapeHtml(user.username)}">${C.icon("trash-2")}Delete</button>
        </div>
      </td>
    </tr>
  `).join("");

  C.$("users").innerHTML = `<div class="table-wrap">
    <table>
      <thead><tr><th>User</th><th>Role</th><th>Status</th><th>2FA</th><th>Updated</th><th>Actions</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;

  document.querySelectorAll("[data-edit-user]").forEach((node) => {
    node.addEventListener("click", () => fillUserForm(node.dataset.editUser));
  });
  document.querySelectorAll("[data-delete-user]").forEach((node) => {
    node.addEventListener("click", () => deleteUser(node.dataset.deleteUser));
  });
  document.querySelectorAll("[data-reset-2fa]").forEach((node) => {
    node.addEventListener("click", () => resetTwoFactor(node.getAttribute("data-reset-2fa")));
  });
}

function fillUserForm(username) {
  const user = state.users.find((item) => item.username === username);
  if (!user) return;
  C.$("adminUsername").value = user.username;
  C.$("adminPassword").value = "";
  C.$("adminRole").value = user.role;
  C.$("adminActive").checked = Boolean(user.active);
  C.setNotice("adminNotice", "");
}

async function loadUsers() {
  const data = await C.api("/api/bootstrap");
  C.updateShell(data);
  if (!data.is_admin) {
    location.href = "/dashboard";
    return;
  }
  state.users = data.users || [];
  state.roles = data.roles || [];
  renderRoles();
  renderUsers();
  C.mountIcons();
}

async function saveUser(event) {
  event.preventDefault();
  C.setNotice("adminNotice", "");
  const payload = {
    username: C.$("adminUsername").value.trim(),
    password: C.$("adminPassword").value,
    role: C.$("adminRole").value,
    active: C.$("adminActive").checked
  };

  C.$("saveUser").disabled = true;
  try {
    await C.api("/api/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    C.$("adminPassword").value = "";
    await loadUsers();
  } catch (error) {
    C.setNotice("adminNotice", error.message);
  } finally {
    C.$("saveUser").disabled = false;
  }
}

async function deleteUser(username) {
  C.setNotice("adminNotice", "");
  if (!confirm(`Delete user ${username}?`)) return;
  try {
    await C.api(`/api/users/${encodeURIComponent(username)}`, { method: "DELETE" });
    await loadUsers();
  } catch (error) {
    C.setNotice("adminNotice", error.message);
  }
}

async function resetTwoFactor(username) {
  C.setNotice("adminNotice", "");
  if (!confirm(`Reset 2FA for ${username}?`)) return;
  try {
    await C.api(`/api/users/${encodeURIComponent(username)}/2fa-reset`, { method: "POST" });
    await loadUsers();
  } catch (error) {
    C.setNotice("adminNotice", error.message);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  C.initShell();
  C.$("userForm").addEventListener("submit", saveUser);
  loadUsers();
});
