"use strict";

/* CoreX Admin Console — live D1-backed data. */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) =>
    Array.from(root.querySelectorAll(selector));

const state = {
    overview: null,
    requests: [],
    sessions: [],
    clients: [],
    requestCursor: null,
    requestHasMore: false,
    requestLoadingMore: false
};

const brokerNames = {
    upstox: "Upstox",
    fyers: "FYERS",
    zerodha: "Zerodha",
    angelone: "Angel One",
    "angel-one": "Angel One"
};

const toast = {
    timeout: null
};

function createElement(tag, className = "", text) {
    const element = document.createElement(tag);

    if (className) element.className = className;
    if (text !== undefined && text !== null) {
        element.textContent = String(text);
    }

    return element;
}

function setText(selector, value) {
    const element = $(selector);
    if (element) element.textContent = String(value ?? "—");
}

function formatNumber(value) {
    return Number(value ?? 0).toLocaleString();
}

function formatTimestamp(seconds, includeDate = true) {
    if (
        seconds === null ||
        seconds === undefined ||
        !Number.isFinite(Number(seconds)) ||
        Number(seconds) <= 0
    ) {
        return "Never";
    }

    const date = new Date(Number(seconds) * 1000);

    if (Number.isNaN(date.getTime())) {
        return "—";
    }

    return date.toLocaleString(
        undefined,
        includeDate
            ? {
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit"
            }
            : {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            }
    );
}

function compactNumber(value) {
    return new Intl.NumberFormat(undefined, {
        notation: "compact",
        maximumFractionDigits: 1
    }).format(Number(value) || 0);
}

function shortId(value) {
    if (typeof value !== "string" || !value) return "—";
    return value.slice(0, 8);
}

function brokerDisplayName(broker) {
    if (typeof broker !== "string" || !broker) return "Unknown";

    return brokerNames[broker.toLowerCase()] || broker;
}

function appendCell(row, text, className = "") {
    const cell = createElement("td", className, text);
    row.appendChild(cell);
    return cell;
}

function renderTableMessage(
    selector,
    colspan,
    message,
    className = "empty-cell"
) {
    const body = $(selector);
    if (!body) return;

    body.replaceChildren();

    const row = document.createElement("tr");
    const cell = createElement("td", className, message);

    cell.colSpan = colspan;
    row.appendChild(cell);
    body.appendChild(row);
}

function setBrokerCell(cell, broker) {
    const normalized = typeof broker === "string" && broker
        ? broker.toLowerCase()
        : "unknown";

    const container = createElement("div", "broker-cell");
    const dot = createElement("span", `broker-dot broker-${normalized}`);

    dot.setAttribute("aria-hidden", "true");

    container.append(
        dot,
        createElement("span", "", brokerDisplayName(broker))
    );

    cell.appendChild(container);
}

function makeStatusPill(status, label) {
    return createElement("span", `result-pill ${status}`, label);
}

function showToast(message) {
    const element = $("#toast");
    if (!element) return;

    window.clearTimeout(toast.timeout);

    element.textContent = message;
    element.classList.add("visible");

    toast.timeout = window.setTimeout(() => {
        element.classList.remove("visible");
    }, 3000);
}

function updateProgress(selector, percent) {
    const element = $(selector);
    if (!element) return;

    const safePercent = Math.max(
        0,
        Math.min(100, Number(percent) || 0)
    );

    element.style.width = `${safePercent}%`;
}

function setDashboardNotice(title, message, mode = "live") {
    setText("#dashboard-status-title", title);
    setText("#dashboard-status-message", message);

    const notice = $("#dashboard-notice");

    const statusTag = $("#data-mode-tag");
    if (statusTag) statusTag.dataset.state = mode;

    const sidebarMode = $(".sidebar-mode");
    if (sidebarMode) sidebarMode.dataset.state = mode;

    if (notice) {
        notice.dataset.state = mode;
        notice.classList.remove("notice-hidden");
    }

    setText(
        "#data-mode-label",
        mode === "error"
            ? "DATA ERROR"
            : mode === "partial"
                ? "PARTIAL DATA"
                : "LIVE DATA"
    );

    setText(
        "#data-mode-title",
        mode === "error"
            ? "Data unavailable"
            : mode === "partial"
                ? "Partial data"
                : "Live data"
    );

    setText(
        "#data-mode-description",
        mode === "error"
            ? "Check connection"
            : mode === "partial"
                ? "Some panels failed"
                : "Connected to Admin API"
    );
}

/* ---------- Authenticated API access ---------- */

async function fetchAdminJson(url, options = {}) {
    const response = await fetch(url, {
        credentials: "same-origin",
        cache: "no-store",
        ...options
    });

    if (response.status === 401) {
        window.location.replace("/login.html");

        const error = new Error("Authentication required");
        error.unauthorized = true;

        throw error;
    }

    if (!response.ok) {
        const error = new Error(
            `Admin API request failed (${response.status})`
        );

        error.status = response.status;
        throw error;
    }

    return response.json();
}

async function loadAdminIdentity() {
    try {
        const data = await fetchAdminJson("/api/v1/admin/me");

        if (
            data.authenticated !== true ||
            typeof data.username !== "string" ||
            !data.username.trim()
        ) {
            throw new Error("Invalid admin identity response");
        }

        const username = data.username.trim();

        setText("#profile-name", username);
        setText("#profile-avatar", Array.from(username)[0].toUpperCase());

        const chip = $("#profile-chip");

        if (chip) {
            chip.title = `Signed in as ${username}`;
        }
    } catch (error) {
        if (error?.unauthorized) return;

        setText("#profile-name", "Admin");
        setText("#profile-avatar", "A");
    }
}

/* ---------- Request log rendering ---------- */

function requestStatus(code) {
    if (Number(code) === 429) return "limited";
    if (Number(code) >= 400) return "error";
    return "success";
}

function normalizeRequest(record) {
    const code = Number(record.status_code ?? 0);

    const clientName = record.client_display_name ||
        (record.corex_client_id
            ? `Client ${shortId(record.corex_client_id)}`
            : "Unattributed");

    return {
        raw: record,
        id: String(record.request_id ?? ""),
        client: clientName,
        broker: record.broker,
        endpoint: `${record.method ?? ""} ${record.path ?? ""}`.trim(),
        time: formatTimestamp(record.created_at, false),
        statusCode: code,
        status: requestStatus(code),
        latency: `${Math.max(0, Number(record.duration_ms ?? 0))} ms`
    };
}

function getFilteredRequests() {
    const query = ($("#request-search")?.value || "")
        .trim()
        .toLowerCase();

    const brokerFilter = $("#broker-filter")?.value || "all";
    const statusFilter = $("#status-filter")?.value || "all";

    return state.requests.map(normalizeRequest).filter(request => {
        const searchable = [
            request.id,
            request.client,
            request.broker,
            brokerDisplayName(request.broker),
            request.endpoint,
            request.time,
            request.statusCode
        ].join(" ").toLowerCase();

        return searchable.includes(query) &&
            (brokerFilter === "all" ||
                request.broker === brokerFilter) &&
            (statusFilter === "all" ||
                request.status === statusFilter);
    });
}

function renderRequests() {
    const body = $("#requests-body");
    const count = $("#request-count");

    if (!body || !count) return;

    const rows = getFilteredRequests();

    body.replaceChildren();

    if (!rows.length) {
        renderTableMessage(
            "#requests-body",
            8,
            state.requests.length
                ? "No logged requests match these filters."
                : "No request logs have been recorded yet."
        );

        count.textContent = state.requests.length
            ? `0 matching requests · ${state.requests.length} records loaded`
            : "0 request records";

        setText("#nav-request-count", state.requests.length);
        return;
    }

    const fragment = document.createDocumentFragment();

    for (const request of rows) {
        const row = document.createElement("tr");

        appendCell(row, shortId(request.id), "request-id");
        appendCell(row, request.client, "client-name");

        const brokerCell = document.createElement("td");
        setBrokerCell(brokerCell, request.broker);
        row.appendChild(brokerCell);

        appendCell(row, request.endpoint, "endpoint-cell");
        appendCell(row, request.time, "time-cell");
        appendCell(row, request.statusCode, "http-code");

        const statusCell = document.createElement("td");

        const statusLabel = {
            success: "Success",
            error: "Error",
            limited: "Rate limited"
        }[request.status] || "Unknown";

        statusCell.appendChild(
            makeStatusPill(request.status, statusLabel)
        );

        row.appendChild(statusCell);
        appendCell(row, request.latency, "time-cell");

        fragment.appendChild(row);
    }

    body.appendChild(fragment);

    count.textContent =
        `Showing ${rows.length} of ${state.requests.length} latest logged requests`;

    setText("#nav-request-count", state.requests.length);
}

/* ---------- OAuth session rendering ---------- */

function sessionView(session) {
    const now = Math.floor(Date.now() / 1000);

    let status = session.status || "unknown";
    let label = status.replaceAll("_", " ");
    let css = "error";

    if (status === "retrieved") {
        status = "completed";
        label = "Retrieved";
        css = "completed";
    } else if (status === "pending" || status === "code_received") {
        if (Number(session.expires_at) <= now) {
            status = "expired";
            label = "Expired";
            css = "expired";
        } else {
            css = "pending";
            label = status === "code_received"
                ? "Code received"
                : "Pending";
        }
    } else if (status === "expired") {
        css = "expired";
        label = "Expired";
    } else if (status === "failed") {
        css = "error";
        label = "Failed";
    }

    let expires = "—";

    if (status === "completed") {
        expires = "Retrieved";
    } else if (status === "expired") {
        expires = "Expired";
    } else if (
        session.status === "pending" ||
        session.status === "code_received"
    ) {
        const secondsLeft = Number(session.expires_at) - now;

        expires = secondsLeft <= 0
            ? "Expired"
            : secondsLeft < 60
                ? `${secondsLeft}s left`
                : `${Math.ceil(secondsLeft / 60)}m left`;
    }

    return { status, label, css, expires };
}

function renderSessions() {
    const body = $("#sessions-body");
    if (!body) return;

    body.replaceChildren();

    if (!state.sessions.length) {
        renderTableMessage(
            "#sessions-body",
            5,
            "No OAuth sessions have been recorded yet."
        );
        return;
    }

    const fragment = document.createDocumentFragment();

    for (const session of state.sessions) {
        const row = document.createElement("tr");

        appendCell(row, shortId(session.session_id), "session-id");

        const brokerCell = document.createElement("td");
        setBrokerCell(brokerCell, session.broker);
        row.appendChild(brokerCell);

        appendCell(
            row,
            formatTimestamp(session.created_at),
            "time-cell"
        );

        const view = sessionView(session);

        appendCell(row, view.expires, "time-cell");

        const statusCell = document.createElement("td");
        statusCell.appendChild(
            makeStatusPill(view.css, view.label)
        );

        row.appendChild(statusCell);
        fragment.appendChild(row);
    }

    body.appendChild(fragment);
}

/* ---------- Registered CoreX client rendering ---------- */

function renderClients() {
    const body = $("#clients-body");
    if (!body) return;

    body.replaceChildren();

    if (!state.clients.length) {
        renderTableMessage(
            "#clients-body",
            7,
            "No CoreX clients are registered yet."
        );
        return;
    }

    const fragment = document.createDocumentFragment();

    for (const client of state.clients) {
        const row = document.createElement("tr");

        appendCell(
            row,
            shortId(client.corex_client_id),
            "request-id"
        );

        appendCell(
            row,
            client.display_name || "Unnamed client",
            "client-name"
        );

        const statusCell = document.createElement("td");

        const statusClass = client.status === "active"
            ? "active"
            : "revoked";

        statusCell.appendChild(
            makeStatusPill(statusClass, client.status || "unknown")
        );

        row.appendChild(statusCell);

        appendCell(
            row,
            formatNumber(client.session_count),
            "time-cell"
        );

        appendCell(
            row,
            formatNumber(client.open_sessions),
            "time-cell"
        );

        appendCell(
            row,
            formatTimestamp(client.last_seen_at),
            "time-cell"
        );

        const actionCell = document.createElement("td");

        if (client.status === "active") {
            const button = createElement(
                "button",
                "button button-secondary button-small",
                "Revoke"
            );

            button.type = "button";
            button.dataset.clientAction = "revoke";
            button.dataset.clientId = client.corex_client_id;

            actionCell.appendChild(button);
        } else {
            actionCell.appendChild(
                createElement("span", "table-footnote", "Revoked")
            );
        }

        row.appendChild(actionCell);
        fragment.appendChild(row);
    }

    body.appendChild(fragment);
}

/* ---------- Overview metrics and chart ---------- */

function updateSessionSummary(sessions) {
    if (!sessions) return;

    setText(
        '[data-session-stat="retrieved"]',
        formatNumber(sessions.retrieved)
    );

    setText(
        '[data-session-stat="active"]',
        formatNumber(
            sessions.active ??
            (Number(sessions.pending ?? 0) +
                Number(sessions.code_received ?? 0))
        )
    );

    setText(
        '[data-session-stat="expired"]',
        formatNumber(sessions.expired)
    );
}

function chartLabel(timestamp, period) {
    const date = new Date(Number(timestamp) * 1000);

    if (Number.isNaN(date.getTime())) return "—";

    if (period === "24h") {
        return date.toLocaleTimeString(undefined, {
            hour: "2-digit"
        });
    }

    if (period === "7d") {
        return date.toLocaleDateString(undefined, {
            weekday: "short"
        });
    }

    return date.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric"
    });
}

function renderChart(overview) {
    const data = Array.isArray(overview?.chart)
        ? overview.chart
        : [];

    const columns = $$("#chart-columns .chart-column");
    const xLabels = $$("#chart-x-labels span");
    const yLabels = $$("#chart-y-labels span");

    const period = overview?.period ||
        $("#period-select")?.value ||
        "24h";

    const maxValue = Math.max(
        0,
        ...data.map(item => Number(item.total) || 0)
    );

    const scaleMax = maxValue > 0
        ? Math.ceil(maxValue / 4) * 4
        : 4;

    columns.forEach((column, index) => {
        const item = data[index] || {
            timestamp: 0,
            total: 0,
            successful: 0
        };

        const total = Math.max(0, Number(item.total) || 0);
        const successful = Math.max(
            0,
            Number(item.successful) || 0
        );

        const height = total > 0
            ? Math.max(2, total / scaleMax * 100)
            : 0;

        column.style.setProperty("--height", `${height}%`);

        const successBar = $(".bar-success", column);

        if (successBar) {
            successBar.style.height =
                `${total ? Math.min(100, successful / total * 100) : 0}%`;
        }

        column.dataset.label = chartLabel(item.timestamp, period);
        column.title =
            `${formatTimestamp(item.timestamp)} · ` +
            `${total} requests · ${successful} successful`;
    });

    yLabels.forEach((label, index) => {
        const fraction = 1 - index / Math.max(1, yLabels.length - 1);

        label.textContent = compactNumber(scaleMax * fraction);
    });

    xLabels.forEach((label, index) => {
        if (!data.length) {
            label.textContent = "—";
            return;
        }

        const dataIndex = Math.round(
            index * (data.length - 1) /
            Math.max(1, xLabels.length - 1)
        );

        label.textContent = chartLabel(
            data[dataIndex].timestamp,
            period
        );
    });

    const periodLabels = {
        "24h": "Last 24 hours",
        "7d": "Last 7 days",
        "30d": "Last 30 days"
    };

    setText(
        "#chart-period-label",
        periodLabels[period] || period
    );

    setText("#chart-data-status", "D1 request logs loaded");

    const chart = $("#traffic-chart");

    if (chart) {
        chart.setAttribute(
            "aria-label",
            `Recorded requests for ${periodLabels[period] || period}`
        );
    }
}

function updateUsage() {
    const recent = state.requests;
    const overview = state.overview;

    const totalPeriodRequests = Number(
        overview?.requests?.total ?? 0
    );

    const successRate = Number(
        overview?.requests?.success_rate ?? 0
    );

    setText("#usage-total", formatNumber(recent.length));
    setText("#usage-success-rate", `${successRate.toFixed(1)}% success`);

    updateProgress("#usage-progress", successRate);

    setText(
        "#usage-scale-left",
        `${formatNumber(recent.length)} recent records`
    );

    setText(
        "#usage-scale-right",
        `${formatNumber(totalPeriodRequests)} in selected period`
    );

    const categories = {
        sessionCreate: 0,
        callback: 0,
        result: 0,
        other: 0
    };

    for (const request of recent) {
        const path = String(request.path || "");

        if (path === "/api/v1/auth/sessions") {
            categories.sessionCreate++;
        } else if (path === "/auth/upstox/callback") {
            categories.callback++;
        } else if (path.endsWith("/result")) {
            categories.result++;
        } else {
            categories.other++;
        }
    }

    const denominator = Math.max(1, recent.length);

    const values = [
        ["#usage-session-create", categories.sessionCreate],
        ["#usage-callback", categories.callback],
        ["#usage-result", categories.result],
        ["#usage-other", categories.other]
    ];

    for (const [selector, count] of values) {
        setText(
            selector,
            `${count} · ${(count / denominator * 100).toFixed(0)}%`
        );
    }
}

function renderMetricSparklines(chart) {
    const data = Array.isArray(chart) ? chart : [];

    const totals = data.map(item =>
        Math.max(0, Number(item.total) || 0)
    );

    const failures = data.map(item =>
        Math.max(
            0,
            (Number(item.total) || 0) -
                (Number(item.successful) || 0)
        )
    );

    function draw(selector, values, label) {
        const bars = $$(`${selector} span`);
        const maximum = Math.max(0, ...values);

        bars.forEach((bar, index) => {
            const dataIndex = Math.round(
                index * (values.length - 1) /
                Math.max(1, bars.length - 1)
            );

            const value = values[dataIndex] ?? 0;
            const height = maximum > 0
                ? value / maximum * 100
                : 0;

            bar.style.setProperty("--bar", `${height}%`);
            bar.title = `${value} ${label}`;
        });
    }

    draw("#requests-sparkline", totals, "requests");
    draw("#failed-sparkline", failures, "failed requests");
}

function updateOverview(overview) {
    state.overview = overview;

    const requests = overview?.requests || {};
    const clients = overview?.clients || {};

    setText(
        '[data-stat="requests"]',
        formatNumber(requests.total)
    );

    setText(
        '[data-stat="success-rate"]',
        Number(requests.success_rate ?? 0).toFixed(1)
    );

    setText(
        '[data-stat="failed"]',
        formatNumber(requests.failed)
    );

    setText(
        '[data-stat="latency"]',
        formatNumber(requests.average_latency_ms)
    );

    setText(
        "#success-count",
        `${formatNumber(requests.successful)} successful`
    );

    const failedPercent = Number(requests.total) > 0
        ? Number(requests.failed) / Number(requests.total) * 100
        : 0;

    setText("#failed-rate", `${failedPercent.toFixed(1)}% of requests`);

    updateProgress("#success-progress", requests.success_rate);

    setText(
        "#request-period-caption",
        `in ${overview.period || "selected period"}`
    );

    setText(
        "#client-count-summary",
        `${formatNumber(clients.active)} active · ` +
        `${formatNumber(clients.revoked)} revoked`
    );

    updateSessionSummary(overview.sessions);
    renderChart(overview);
    renderMetricSparklines(overview.chart);
    updateUsage();
}

/* ---------- Load all live dashboard panels ---------- */

async function loadDashboardData() {
    const period = $("#period-select")?.value || "24h";
    const refreshButton = $("#refresh-button");

    if (refreshButton) refreshButton.disabled = true;

    setDashboardNotice(
        "Loading live data",
        "Fetching metrics, requests, sessions and clients from the Admin API…",
        "partial"
    );

    const jobs = [
        [
            "overview",
            `/api/v1/admin/overview?period=${encodeURIComponent(period)}`
        ],
        ["requests", "/api/v1/admin/requests?limit=100"],
        ["sessions", "/api/v1/admin/sessions?limit=100"],
        ["clients", "/api/v1/admin/clients?limit=100"]
    ];

    const results = await Promise.allSettled(
        jobs.map(async ([key, url]) => ({
            key,
            data: await fetchAdminJson(url)
        }))
    );

    if (
        results.some(
            result =>
                result.status === "rejected" &&
                result.reason?.unauthorized
        )
    ) {
        if (refreshButton) refreshButton.disabled = false;
        return;
    }

    const failures = [];

    for (let index = 0; index < results.length; index++) {
        const result = results[index];
        const key = jobs[index][0];

        if (result.status === "rejected") {
            failures.push(key);

            if (key === "overview" && !state.overview) {
                setDashboardNotice(
                    "Overview unavailable",
                    "Metrics couldn't be loaded. Check the Worker logs.",
                    "error"
                );
            } else if (key === "requests" && !state.requests.length) {
                renderTableMessage(
                    "#requests-body",
                    8,
                    "Request logs couldn't be loaded."
                );
            } else if (key === "sessions" && !state.sessions.length) {
                renderTableMessage(
                    "#sessions-body",
                    5,
                    "Sessions couldn't be loaded."
                );
            } else if (key === "clients" && !state.clients.length) {
                renderTableMessage(
                    "#clients-body",
                    7,
                    "Clients couldn't be loaded."
                );
            }

            continue;
        }

        const data = result.value.data;

        if (key === "overview") {
            updateOverview(data);
        } else if (key === "requests") {
            state.requests = Array.isArray(data.items)
                ? data.items
                : [];

            renderRequests();
            updateUsage();
        } else if (key === "sessions") {
            state.sessions = Array.isArray(data.items)
                ? data.items
                : [];

            renderSessions();
        } else if (key === "clients") {
            state.clients = Array.isArray(data.items)
                ? data.items
                : [];

            renderClients();
        }
    }

    if (refreshButton) refreshButton.disabled = false;

    if (failures.length === 0) {
        setDashboardNotice(
            "Live data connected",
            `Updated ${new Date().toLocaleTimeString()}. ` +
            "Metrics and records loaded from the authenticated Admin API.",
            "live"
        );
    } else {
        setDashboardNotice(
            "Some data could not be loaded",
            `Failed panels: ${failures.join(", ")}. ` +
            "Check Worker logs if this continues.",
            "partial"
        );
    }
}

/* ---------- CSV export ---------- */

async function exportCsv() {
    const rows = getFilteredRequests();

    if (!rows.length) {
        showToast("No live request records match the current filters.");
        return;
    }

    const columns = [
        ["request_id", "id"],
        ["client", "client"],
        ["broker", "broker"],
        ["endpoint", "endpoint"],
        ["time", "time"],
        ["http_status", "statusCode"],
        ["result", "status"],
        ["latency", "latency"]
    ];

    function escapeCsv(value) {
        let text = String(value ?? "");

        // Reduce CSV formula injection risk.
        if (/^[=+@\-\t\r]/.test(text)) {
            text = `'${text}`;
        }

        return `"${text.replace(/"/g, '""')}"`;
    }

    const csv = [
        columns.map(([header]) => escapeCsv(header)).join(","),
        ...rows.map(row =>
            columns
                .map(([, key]) => escapeCsv(row[key]))
                .join(",")
        )
    ].join("\r\n");

    const blob = new Blob(
        ["\uFEFF", csv],
        { type: "text/csv;charset=utf-8;" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "corex-live-requests.csv";
    link.style.display = "none";

    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);

    showToast(`Exported ${rows.length} live request records.`);
}

/* ---------- Client revocation ---------- */

async function revokeClient(clientId, button) {
    if (
        !clientId ||
        !window.confirm(
            "Revoke this CoreX client? Its active OAuth sessions will be expired."
        )
    ) {
        return;
    }

    button.disabled = true;

    try {
        const result = await fetchAdminJson(
            `/api/v1/admin/clients/${encodeURIComponent(clientId)}/revoke`,
            { method: "POST" }
        );

        showToast(
            `Client revoked. ${Number(result.expiredSessions ?? 0)} ` +
            "active session(s) expired."
        );

        await loadDashboardData();
    } catch (error) {
        if (!error?.unauthorized) {
            showToast(
                error?.status === 404
                    ? "Client was not found."
                    : "Client revocation failed. Check Worker logs."
            );
        }

        button.disabled = false;
    }
}

/* ---------- Navigation and event handlers ---------- */

async function copyEndpoint(path) {
    try {
        await navigator.clipboard.writeText(path);
        showToast(`Copied endpoint path: ${path}`);
    } catch {
        showToast(
            "Clipboard unavailable. Select and copy the endpoint manually."
        );
    }
}

function setupNavigation() {
    const links = $$(".nav-link[data-nav]");
    const breadcrumb = $("#breadcrumb-current");

    const names = new Map(
        links.map(link => [
            link.dataset.nav,
            link.querySelector("span")?.textContent.trim() ||
                link.textContent.trim()
        ])
    );

    function setActive(id) {
        links.forEach(link => {
            const active = link.dataset.nav === id;

            link.classList.toggle("active", active);

            if (active) {
                link.setAttribute("aria-current", "page");
            } else {
                link.removeAttribute("aria-current");
            }
        });

        if (breadcrumb) {
            breadcrumb.textContent = names.get(id) || "Overview";
        }
    }

    links.forEach(link => {
        link.addEventListener("click", () => setActive(link.dataset.nav));
    });

    if (!("IntersectionObserver" in window)) return;

    const sections = links
        .map(link => document.getElementById(link.dataset.nav))
        .filter(Boolean);

    const observer = new IntersectionObserver(entries => {
        const visible = entries
            .filter(entry => entry.isIntersecting)
            .sort((a, b) => b.intersectionRatio - a.intersectionRatio);

        if (visible.length) {
            setActive(visible[0].target.id);
        }
    }, {
        rootMargin: "-18% 0px -65% 0px",
        threshold: [0, 0.1, 0.25, 0.5]
    });

    sections.forEach(section => observer.observe(section));
}

function setupEvents() {
    $("#request-search")?.addEventListener("input", renderRequests);
    $("#broker-filter")?.addEventListener("change", renderRequests);
    $("#status-filter")?.addEventListener("change", renderRequests);

    $("#export-button")?.addEventListener("click", exportCsv);

    $("#period-select")?.addEventListener(
        "change",
        loadDashboardData
    );

    $("#refresh-button")?.addEventListener("click", async event => {
        const button = event.currentTarget;

        button.classList.add("is-refreshing");

        await loadDashboardData();

        button.classList.remove("is-refreshing");
    });

    $("#dismiss-notice")?.addEventListener("click", () => {
        $("#dashboard-notice")?.classList.add("notice-hidden");
    });

    $$(".copy-button[data-copy]").forEach(button => {
        button.addEventListener("click", () => {
            if (button.dataset.copy) {
                copyEndpoint(button.dataset.copy);
            }
        });
    });

    $("#clients-body")?.addEventListener("click", event => {
        const button = event.target.closest(
            "[data-client-action='revoke']"
        );

        if (button) {
            revokeClient(button.dataset.clientId, button);
        }
    });

    $("#logout-button")?.addEventListener("click", async event => {
        const button = event.currentTarget;
        button.disabled = true;

        try {
            const response = await fetch("/api/v1/admin/logout", {
                method: "POST",
                credentials: "same-origin",
                cache: "no-store"
            });

            if (response.ok) {
                window.location.replace("/login.html");
                return;
            }
        } catch {
            // Keep the page open if logout cannot reach the server.
        }

        button.disabled = false;
        showToast("Unable to sign out. Please try again.");
    });
}

function resetChartWhileLoading() {
    $$("#chart-columns .chart-column").forEach(column => {
        column.style.setProperty("--height", "0%");

        const successBar = $(".bar-success", column);

        if (successBar) {
            successBar.style.height = "0%";
        }
    });

    $$("#requests-sparkline span, #failed-sparkline span")
        .forEach(bar => bar.style.setProperty("--bar", "0%"));
}

function initDashboard() {
    resetChartWhileLoading();
    setupNavigation();
    setupEvents();

    loadAdminIdentity();
    loadDashboardData();
}

if (document.readyState === "loading") {
    document.addEventListener(
        "DOMContentLoaded",
        initDashboard,
        { once: true }
    );
} else {
    initDashboard();
}