const API = "/api/v3/admin";

const $ = selector => document.querySelector(selector);

const state = {
    period: "24h",
    requests: [],
    requestLimit: 25,
    clients: [],
    sessions: []
};

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[character]);
}

function formatDate(value) {
    if (!value) return "—";

    const date = new Date(value);

    return Number.isFinite(date.getTime())
        ? date.toLocaleString()
        : "—";
}

function statusBadge(status) {
    const style = {
        active: "success",
        ready: "success",
        retrieved: "success",
        failed: "danger",
        revoked: "danger",
        expired: "warning",
        cancelled: "warning",
        pending: "",
        processing: ""
    }[status] ?? "";

    return `<span class="badge ${style}">${escapeHtml(status)}</span>`;
}

function showToast(message) {
    const toast = $("#toast");

    toast.textContent = message;
    toast.classList.add("visible");

    setTimeout(() => toast.classList.remove("visible"), 3000);
}

async function adminFetch(path, options = {}) {
    const response = await fetch(`${API}${path}`, {
        credentials: "same-origin",
        ...options,
        headers: {
            Accept: "application/json",
            ...(options.body !== undefined && {
                "Content-Type": "application/json"
            }),
            ...options.headers
        }
    });

    const body = await response.json().catch(() => null);

    if (response.status === 401) {
        window.location.replace("/login.html");
        throw new Error("Administrator session expired.");
    }

    if (!response.ok) {
        throw new Error(
            body?.message || `Request failed (${response.status}).`
        );
    }

    return body;
}

function showView(name) {
    document.querySelectorAll(".view").forEach(view => {
        view.classList.toggle(
            "active",
            view.id === `view-${name}`
        );
    });

    document.querySelectorAll("[data-view-target]").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.viewTarget === name
        );
    });

    const titles = {
        overview: "Overview",
        requests: "Requests",
        clients: "Clients",
        sessions: "Sessions",
        audit: "Audit history"
    };

    $("#page-title").textContent = titles[name] ?? "CoreX";
}

function renderOverview(data) {
    $("#request-total").textContent = data.requests.total.toLocaleString();

    $("#request-success-rate").textContent =
        `${data.requests.successRate.toFixed(1)}%`;

    $("#request-success-count").textContent =
        `${data.requests.successful} successful · ${data.requests.failed} failed`;

    $("#active-clients").textContent = data.clients.active;
    $("#total-clients").textContent = `${data.clients.total} registered`;

    $("#session-total").textContent = data.sessions.total;
    $("#active-sessions").textContent = `${data.sessions.active} active`;

    $("#requests-today").textContent =
        data.usage.requestsToday.toLocaleString();

    const brokerStats = $("#broker-stats");

    brokerStats.innerHTML = data.brokerStats.length
        ? data.brokerStats.map(item => `
            <div class="data-row">
                <div>
                    <strong>${escapeHtml(item.broker)}</strong>
                    <div>
                        <span>
                            ${item.successful} successful · ${item.failed} failed
                        </span>
                    </div>
                </div>
                <div>
                    <strong>${item.successRate.toFixed(1)}%</strong>
                    <progress max="100" value="${item.successRate}"></progress>
                </div>
            </div>
        `).join("")
        : `<p class="empty">No completed exchanges in this period.</p>`;

    const failureReasons = $("#failure-reasons");

    failureReasons.innerHTML = data.failureReasons.length
        ? data.failureReasons.map(item => `
            <div class="data-row">
                <strong>${escapeHtml(item.code)}</strong>
                <span>${item.count}</span>
            </div>
        `).join("")
        : `<p class="empty">No failed authentication sessions.</p>`;

    const statuses = [
        "pending",
        "codeReceived",
        "processing",
        "ready",
        "retrieved",
        "failed",
        "expired",
        "cancelled"
    ];

    const labels = {
        codeReceived: "Code received"
    };

    $("#session-breakdown").innerHTML = statuses.map(status => `
        <div class="status-item">
            <span>${escapeHtml(labels[status] ?? status)}</span>
            <strong>${data.sessions[status] ?? 0}</strong>
        </div>
    `).join("");
}

function requestMatches(item) {
    const search = $("#request-search").value.trim().toLowerCase();
    const status = $("#request-status-filter").value;
    const broker = $("#request-broker-filter").value.trim().toLowerCase();

    const haystack = [
        item.requestId,
        item.path,
        item.clientName,
        item.clientId,
        item.broker
    ].join(" ").toLowerCase();

    if (search && !haystack.includes(search)) return false;

    if (broker && item.broker !== broker) return false;

    if (status && !String(item.statusCode).startsWith(status[0])) {
        return false;
    }

    return true;
}

function renderRequests() {
    const items = state.requests.filter(requestMatches);

    $("#requests-body").innerHTML = items.length
        ? items.map(item => `
            <tr>
                <td>${escapeHtml(formatDate(item.createdAt))}</td>
                <td><span class="mono">${escapeHtml(item.method)}</span></td>
                <td class="mono">${escapeHtml(item.path)}</td>
                <td>${statusBadge(String(item.statusCode))}</td>
                <td>${item.durationMs} ms</td>
                <td>${escapeHtml(item.clientName ?? item.clientId ?? "—")}</td>
                <td>${escapeHtml(item.broker ?? "—")}</td>
            </tr>
        `).join("")
        : `<tr><td colspan="7" class="empty">No matching request records.</td></tr>`;

    $("#request-count").textContent =
        `${items.length} matching records · ${state.requests.length} loaded`;
}

async function loadRequests(reset = true) {
    if (reset) {
        state.requests = [];
    }

    const offset = reset ? 0 : state.requests.length;

    const params = new URLSearchParams({
        period: state.period,
        limit: String(state.requestLimit),
        offset: String(offset)
    });

    const data = await adminFetch(`/requests?${params}`);

    state.requests.push(...data.items);

    renderRequests();

    $("#load-more-requests").hidden =
        data.items.length < state.requestLimit;
}

async function loadOverview() {
    const data = await adminFetch(
        `/overview?period=${encodeURIComponent(state.period)}`
    );

    renderOverview(data);
}

async function loadClients() {
    const data = await adminFetch("/clients?limit=100");

    state.clients = data.items;
    renderClients();
}

function renderClients() {
    const search = $("#client-search").value.trim().toLowerCase();

    const items = state.clients.filter(client =>
        `${client.displayName} ${client.clientId}`
            .toLowerCase()
            .includes(search)
    );

    $("#client-count").textContent =
        `${items.length} displayed · ${state.clients.length} registered`;

    $("#clients-body").innerHTML = items.length
        ? items.map(client => {
            const hasAuth = client.scopes.includes("auth");
            const active = client.status === "active";

            return `
                <tr>
                    <td>
                        <strong>${escapeHtml(client.displayName)}</strong>
                        <div class="muted mono">${escapeHtml(client.clientId)}</div>
                    </td>
                    <td class="mono">•••• ${escapeHtml(client.keyHint)}</td>
                    <td>${escapeHtml(client.scopes.join(", ") || "None")}</td>
                    <td>${statusBadge(client.status)}</td>
                    <td>${client.openSessions} open · ${client.totalSessions} total</td>
                    <td>${escapeHtml(formatDate(client.lastSeenAt))}</td>
                    <td>
                        <div class="row-actions">
                            <button class="button secondary"
                                data-client-details="${escapeHtml(client.clientId)}">
                                Details
                            </button>

                            <button class="button secondary"
                                data-client-scopes="${escapeHtml(client.clientId)}"
                                ${!active ? "disabled" : ""}>
                                ${hasAuth ? "Disable auth" : "Enable auth"}
                            </button>

                            <button class="button danger"
                                data-client-revoke="${escapeHtml(client.clientId)}"
                                ${!active ? "disabled" : ""}>
                                Revoke
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join("")
        : `<tr><td colspan="7" class="empty">No clients found.</td></tr>`;
}

async function loadSessions() {
    const params = new URLSearchParams({ limit: "100" });

    const status = $("#session-status-filter").value;
    const broker = $("#session-broker-filter").value.trim().toLowerCase();
    const version = $("#session-version-filter").value;

    if (status) params.set("status", status);
    if (broker) params.set("broker", broker);
    if (version) params.set("apiVersion", version);

    const data = await adminFetch(`/sessions?${params}`);

    state.sessions = data.items;
    renderSessions();
}

function renderSessions() {
    $("#sessions-body").innerHTML = state.sessions.length
        ? state.sessions.map(session => {
            const active = ["pending", "processing", "ready"]
                .includes(session.status);

            return `
                <tr>
                    <td class="mono">${escapeHtml(session.sessionId)}</td>
                    <td>${escapeHtml(session.clientName ?? session.clientId ?? "—")}</td>
                    <td>${escapeHtml(session.broker)}</td>
                    <td>V${session.apiVersion}</td>
                    <td>${statusBadge(session.status)}</td>
                    <td>${escapeHtml(formatDate(session.createdAt))}</td>
                    <td>
                        <div class="row-actions">
                            <button class="button secondary"
                                data-session-details="${escapeHtml(session.sessionId)}">
                                Details
                            </button>
                            ${active ? `
                                <button class="button danger"
                                    data-session-invalidate="${escapeHtml(session.sessionId)}">
                                    Invalidate
                                </button>
                            ` : ""}
                        </div>
                    </td>
                </tr>
            `;
        }).join("")
        : `<tr><td colspan="7" class="empty">No matching sessions.</td></tr>`;
}

async function loadAudit() {
    const data = await adminFetch("/audit?limit=100");

    $("#audit-body").innerHTML = data.items.length
        ? data.items.map(item => `
            <tr>
                <td>${escapeHtml(formatDate(item.at))}</td>
                <td>${escapeHtml(item.actor)}</td>
                <td>${escapeHtml(item.action)}</td>
                <td>${escapeHtml(item.targetType)}</td>
                <td class="mono">${escapeHtml(item.targetId)}</td>
            </tr>
        `).join("")
        : `<tr><td colspan="5" class="empty">No administrative changes recorded.</td></tr>`;
}

async function refreshDashboard() {
    await Promise.all([
        loadOverview(),
        loadRequests(true),
        loadClients(),
        loadSessions(),
        loadAudit()
    ]);
}

function showClientKey(apiKey) {
    $("#new-api-key").value = apiKey;
    $("#api-key-dialog").showModal();
}

async function showClientDetails(clientId) {
    const client = await adminFetch(
        `/clients/${encodeURIComponent(clientId)}`
    );

    const fields = [
        ["Client ID", client.clientId],
        ["Display name", client.displayName],
        ["Key hint", `•••• ${client.keyHint}`],
        ["Scopes", client.scopes.join(", ") || "None"],
        ["Status", client.status],
        ["Created", formatDate(client.createdAt)],
        ["Created by", client.createdBy],
        ["Last seen", formatDate(client.lastSeenAt)],
        ["Total sessions", client.totalSessions],
        ["Open sessions", client.openSessions]
    ];

    $("#client-details").innerHTML = fields.map(([label, value]) => `
        <dt>${escapeHtml(label)}</dt>
        <dd>${escapeHtml(value)}</dd>
    `).join("");

    $("#client-dialog").showModal();
}

async function showSessionDetails(sessionId) {
    const session = await adminFetch(
        `/sessions/${encodeURIComponent(sessionId)}`
    );

    const fields = [
        ["Session ID", session.sessionId],
        ["Client", session.clientName ?? session.clientId],
        ["Broker", session.broker],
        ["Provider application ID", session.providerAppId],
        ["API version", `V${session.apiVersion}`],
        ["Status", session.status],
        ["Created", formatDate(session.createdAt)],
        ["Expires", formatDate(session.expiresAt)],
        ["Callback received", formatDate(session.callbackReceivedAt)],
        ["Retrieved", formatDate(session.retrievedAt)],
        ["Failure reason", session.failureCode ?? "—"],
        ["Authorization code present", session.hasAuthorizationCode ? "Yes" : "No"],
        ["Encrypted result present", session.hasResult ? "Yes" : "No"]
    ];

    $("#session-details").innerHTML = fields.map(([label, value]) => `
        <dt>${escapeHtml(label)}</dt>
        <dd>${escapeHtml(value)}</dd>
    `).join("");

    $("#session-dialog").showModal();
}

async function createClient(event) {
    event.preventDefault();

    const displayName = $("#client-display-name").value.trim();

    if (!displayName) return;

    const button = event.submitter;
    button.disabled = true;

    try {
        const result = await adminFetch("/clients", {
            method: "POST",
            body: JSON.stringify({ displayName })
        });

        $("#create-client-form").reset();

        // The key is held only for this dialog and never saved in dashboard state.
        showClientKey(result.apiKey);

        await Promise.all([loadClients(), loadAudit(), loadOverview()]);
        showToast("Client created.");
    } catch (error) {
        showToast(error.message);
    } finally {
        button.disabled = false;
    }
}

async function handleClientAction(event) {
    const details = event.target.closest("[data-client-details]");
    const scopes = event.target.closest("[data-client-scopes]");
    const revoke = event.target.closest("[data-client-revoke]");

    try {
        if (details) {
            await showClientDetails(details.dataset.clientDetails);
        }

        if (scopes) {
            const client = state.clients.find(
                item => item.clientId === scopes.dataset.clientScopes
            );

            if (!client) return;

            const nextScopes = client.scopes.includes("auth")
                ? []
                : ["auth"];

            await adminFetch(
                `/clients/${encodeURIComponent(client.clientId)}/scopes`,
                {
                    method: "PATCH",
                    body: JSON.stringify({ scopes: nextScopes })
                }
            );

            await Promise.all([loadClients(), loadAudit()]);
            showToast("Client scopes updated.");
        }

        if (revoke) {
            const clientId = revoke.dataset.clientRevoke;

            if (!confirm("Revoke this client and cancel its unfinished sessions?")) {
                return;
            }

            await adminFetch(
                `/clients/${encodeURIComponent(clientId)}/revoke`,
                { method: "POST" }
            );

            await Promise.all([
                loadClients(),
                loadSessions(),
                loadAudit(),
                loadOverview()
            ]);

            showToast("Client revoked.");
        }
    } catch (error) {
        showToast(error.message);
    }
}

async function handleSessionAction(event) {
    const details = event.target.closest("[data-session-details]");
    const invalidate = event.target.closest("[data-session-invalidate]");

    try {
        if (details) {
            await showSessionDetails(details.dataset.sessionDetails);
        }

        if (invalidate) {
            const sessionId = invalidate.dataset.sessionInvalidate;

            if (!confirm("Invalidate this authentication session?")) {
                return;
            }

            await adminFetch(
                `/sessions/${encodeURIComponent(sessionId)}/invalidate`,
                { method: "POST" }
            );

            await Promise.all([
                loadSessions(),
                loadAudit(),
                loadOverview()
            ]);

            showToast("Session invalidated.");
        }
    } catch (error) {
        showToast(error.message);
    }
}

async function logout() {
    try {
        await adminFetch("/logout", { method: "POST" });
    } finally {
        window.location.replace("/login.html");
    }
}

function bindEvents() {
    document.querySelectorAll("[data-view-target]").forEach(button => {
        button.addEventListener("click", () => {
            showView(button.dataset.viewTarget);
        });
    });

    document.querySelectorAll("[data-go-view]").forEach(button => {
        button.addEventListener("click", () => {
            showView(button.dataset.goView);
        });
    });

    $("#period-select").addEventListener("change", async event => {
        state.period = event.target.value;

        try {
            await Promise.all([
                loadOverview(),
                loadRequests(true)
            ]);
        } catch (error) {
            showToast(error.message);
        }
    });

    $("#refresh-button").addEventListener("click", async () => {
        try {
            await refreshDashboard();
            showToast("Dashboard refreshed.");
        } catch (error) {
            showToast(error.message);
        }
    });

    $("#logout-button").addEventListener("click", logout);

    $("#create-client-form").addEventListener("submit", createClient);

    $("#clients-body").addEventListener("click", handleClientAction);
    $("#sessions-body").addEventListener("click", handleSessionAction);

    $("#client-search").addEventListener("input", renderClients);

    [
        "#request-search",
        "#request-status-filter",
        "#request-broker-filter"
    ].forEach(selector => {
        $(selector).addEventListener("input", renderRequests);
        $(selector).addEventListener("change", renderRequests);
    });

    [
        "#session-status-filter",
        "#session-broker-filter",
        "#session-version-filter"
    ].forEach(selector => {
        $(selector).addEventListener("change", () => {
            loadSessions().catch(error => showToast(error.message));
        });
    });

    $("#load-more-requests").addEventListener("click", async () => {
        const button = $("#load-more-requests");
        button.disabled = true;

        try {
            const offset = state.requests.length;

            const params = new URLSearchParams({
                period: state.period,
                limit: String(state.requestLimit),
                offset: String(offset)
            });

            const data = await adminFetch(`/requests?${params}`);

            state.requests.push(...data.items);
            renderRequests();

            button.hidden = data.items.length < state.requestLimit;
        } catch (error) {
            showToast(error.message);
        } finally {
            button.disabled = false;
        }
    });

    $("#copy-api-key").addEventListener("click", async () => {
        try {
            await navigator.clipboard.writeText($("#new-api-key").value);
            showToast("API key copied.");
        } catch {
            $("#new-api-key").select();
            showToast("Select and copy the key manually.");
        }
    });

    $("#api-key-dialog").addEventListener("close", () => {
        $("#new-api-key").value = "";
    });
}

async function initializeDashboard() {
    bindEvents();

    try {
        const identity = await adminFetch("/me");
        $("#admin-name").textContent = identity.username;

        await refreshDashboard();
    } catch (error) {
        showToast(error.message);
    }
}

initializeDashboard();