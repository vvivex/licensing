(() => {
  "use strict";

  const apiUrlKey = "vulonzLicenseApiUrl";
  const sessionTokenKey = "vulonzLicenseAdminToken";
  const loginView = document.querySelector("#login-view");
  const dashboardView = document.querySelector("#dashboard-view");
  const loginForm = document.querySelector("#login-form");
  const serverUrlInput = document.querySelector("#server-url");
  const passwordInput = document.querySelector("#admin-password");
  const loginMessage = document.querySelector("#login-message");
  const dashboardMessage = document.querySelector("#dashboard-message");
  const keyList = document.querySelector("#key-list");
  const emptyState = document.querySelector("#empty-state");
  const newKeyPanel = document.querySelector("#new-key");
  const newKeyValue = document.querySelector("#new-key-value");
  const createKeyButton = document.querySelector("#create-key");
  const apiOrigin = localStorage.getItem(apiUrlKey) || "";

  serverUrlInput.value = apiOrigin;

  function showMessage(element, message, kind = "") {
    element.textContent = message;
    element.dataset.kind = kind;
  }

  function normalizeApiOrigin(value) {
    const url = new URL(value.trim());
    const localDevelopment = ["localhost", "127.0.0.1"].includes(url.hostname);
    if (
      (url.protocol !== "https:" && !(localDevelopment && url.protocol === "http:")) ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) {
      throw new Error("Enter the HTTPS base URL for your Render service.");
    }
    return url.origin;
  }

  async function apiRequest(path, { method = "GET", body, token } = {}) {
    const origin = normalizeApiOrigin(serverUrlInput.value);
    const headers = { Accept: "application/json" };
    const activeToken =
      token === undefined ? sessionStorage.getItem(sessionTokenKey) : token;
    if (activeToken) {
      headers.Authorization = `Bearer ${activeToken}`;
    }
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    let response;
    try {
      response = await fetch(`${origin}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        mode: "cors",
        credentials: "omit",
        cache: "no-store",
      });
    } catch {
      throw new Error(
        "Could not reach the server. Check its URL, deployment, and DASHBOARD_ORIGIN setting."
      );
    }

    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(result.error || `Request failed (${response.status}).`);
      error.status = response.status;
      throw error;
    }
    return result;
  }

  function showLogin() {
    dashboardView.hidden = true;
    loginView.hidden = false;
  }

  function showDashboard() {
    loginView.hidden = true;
    dashboardView.hidden = false;
  }

  function makeCell(text) {
    const cell = document.createElement("td");
    cell.textContent = text;
    return cell;
  }

  function makeActionButton(label, action, id, className = "") {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.dataset.action = action;
    button.dataset.id = String(id);
    if (className) {
      button.className = className;
    }
    return button;
  }

  function renderKeys(keys) {
    keyList.replaceChildren();
    for (const key of keys) {
      const row = document.createElement("tr");
      row.append(makeCell(key.masked_key));

      const statusCell = document.createElement("td");
      const status = document.createElement("span");
      status.className = `status-pill${key.status === "revoked" ? " revoked" : ""}`;
      status.textContent = key.status;
      statusCell.append(status);
      row.append(statusCell);

      row.append(makeCell(key.created_at));
      row.append(makeCell(key.device_bound ? "Bound" : "Unbound"));

      const actionsCell = document.createElement("td");
      const actions = document.createElement("div");
      actions.className = "row-actions";
      if (key.status === "active") {
        actions.append(makeActionButton("Reset device", "reset", key.id));
        actions.append(makeActionButton("Revoke", "revoke", key.id, "revoke"));
      } else {
        actions.append(document.createTextNode("—"));
      }
      actionsCell.append(actions);
      row.append(actionsCell);
      keyList.append(row);
    }
    emptyState.hidden = keys.length !== 0;
  }

  async function loadKeys() {
    try {
      const result = await apiRequest("/api/admin/keys");
      renderKeys(result.keys);
      showDashboard();
    } catch (error) {
      if (error.status === 401) {
        sessionStorage.removeItem(sessionTokenKey);
        showLogin();
        showMessage(loginMessage, "Your sign-in expired. Please sign in again.", "error");
        return;
      }
      showDashboard();
      showMessage(dashboardMessage, error.message, "error");
    }
  }

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submitButton = loginForm.querySelector('button[type="submit"]');
    submitButton.disabled = true;
    showMessage(loginMessage, "Signing in…");

    try {
      const newOrigin = normalizeApiOrigin(serverUrlInput.value);
      if (newOrigin !== localStorage.getItem(apiUrlKey)) {
        sessionStorage.removeItem(sessionTokenKey);
      }
      serverUrlInput.value = newOrigin;
      localStorage.setItem(apiUrlKey, newOrigin);
      const result = await apiRequest("/api/admin/login", {
        method: "POST",
        body: { password: passwordInput.value },
        token: "",
      });
      sessionStorage.setItem(sessionTokenKey, result.token);
      passwordInput.value = "";
      showMessage(loginMessage, "");
      await loadKeys();
    } catch (error) {
      showMessage(loginMessage, error.message, "error");
    } finally {
      submitButton.disabled = false;
    }
  });

  createKeyButton.addEventListener("click", async () => {
    createKeyButton.disabled = true;
    newKeyPanel.hidden = true;
    try {
      const result = await apiRequest("/api/admin/keys", {
        method: "POST",
        body: {},
      });
      newKeyValue.textContent = result.key;
      newKeyPanel.hidden = false;
      renderKeys(result.keys);
      showMessage(dashboardMessage, "Key created. Copy it now; it will not be shown again.", "success");
    } catch (error) {
      showMessage(dashboardMessage, error.message, "error");
      if (error.status === 401) {
        sessionStorage.removeItem(sessionTokenKey);
        showLogin();
      }
    } finally {
      createKeyButton.disabled = false;
    }
  });

  keyList.addEventListener("click", async (event) => {
    if (!(event.target instanceof Element)) {
      return;
    }
    const button = event.target.closest("button[data-action]");
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    const { action, id } = button.dataset;
    if (action === "revoke" && !window.confirm("Revoke this lifetime key?")) {
      return;
    }
    button.disabled = true;
    try {
      await apiRequest(`/api/admin/keys/${encodeURIComponent(id)}/${action === "reset" ? "reset-device" : "revoke"}`, {
        method: "POST",
        body: {},
      });
      await loadKeys();
      showMessage(
        dashboardMessage,
        action === "reset" ? "Device binding reset." : "Key revoked.",
        "success"
      );
    } catch (error) {
      showMessage(dashboardMessage, error.message, "error");
    } finally {
      button.disabled = false;
    }
  });

  document.querySelector("#copy-key").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(newKeyValue.textContent);
      showMessage(dashboardMessage, "Key copied to clipboard.", "success");
    } catch {
      showMessage(dashboardMessage, "Copy failed. Select and copy the key manually.", "error");
    }
  });

  document.querySelector("#sign-out").addEventListener("click", async () => {
    try {
      await apiRequest("/api/admin/logout", { method: "POST", body: {} });
    } catch {
      showMessage(dashboardMessage, "Could not contact the server to end the session.", "error");
    } finally {
      sessionStorage.removeItem(sessionTokenKey);
      newKeyPanel.hidden = true;
      showLogin();
      showMessage(loginMessage, "Signed out.");
    }
  });

  if (sessionStorage.getItem(sessionTokenKey) && apiOrigin) {
    loadKeys();
  }
})();
