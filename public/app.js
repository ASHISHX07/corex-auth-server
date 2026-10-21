"use strict";

/*
 * CoreX Admin Console — UI preview.
 *
 * All request records and metrics below are illustrative.
 * Replace this preview data source with authenticated API/D1
 * integration when the dashboard backend is ready.
 */

const demoRequests = [
    {
        id: "req_8F2A3C",
        client: "Ashish",
        broker: "upstox",
        endpoint: "POST /api/v1/auth/sessions",
        time: "10:42:18",
        statusCode: 201,
        status: "success",
        latency: "184 ms"
    },
    {
        id: "req_7B91DE",
        client: "CoreX Desktop",
        broker: "upstox",
        endpoint: "GET /api/v1/auth/sessions/:id/result",
        time: "10:41:52",
        statusCode: 200,
        status: "success",
        latency: "96 ms"
    },
    {
        id: "req_3D6A14",
        client: "Ashish",
        broker: "fyers",
        endpoint: "POST /api/v1/auth/sessions",
        time: "10:40:37",
        statusCode: 401,
        status: "error",
        latency: "42 ms"
    },
    {
        id: "req_92CE50",
        client: "CoreX Desktop",
        broker: "upstox",
        endpoint: "GET /api/v1/auth/sessions/:id/result",
        time: "10:39:09",
        statusCode: 202,
        status: "success",
        latency: "73 ms"
    },
    {
        id: "req_46F18B",
        client: "Ashish",
        broker: "zerodha",
        endpoint: "POST /api/v1/auth/sessions",
        time: "10:37:44",
        statusCode: 429,
        status: "limited",
        latency: "8 ms"
    },
    {
        id: "req_C802AD",
        client: "CoreX Desktop",
        broker: "upstox",
        endpoint: "GET /api/health",
        time: "10:35:16",
        statusCode: 200,
        status: "success",
        latency: "21 ms"
    }
];

const demoSessions = [
    {
        id: "7d4a...c91f",
        broker: "upstox",
        created: "10:42:18",
        expires: "04m 12s",
        status: "completed"
    },
    {
        id: "9b16...a030",
        broker: "upstox",
        created: "10:39:09",
        expires: "04m 48s",
        status: "completed"
    },
    {
        id: "a821...7bc3",
        broker: "fyers",
        created: "10:35:42",
        expires: "02m 31s",
        status: "pending"
    },
    {
        id: "2c54...e109",
        broker: "zerodha",
        created: "10:21:05",
        expires: "Expired",
        status: "expired"
    }
];

const brokerNames = {
    upstox: "Upstox",
    fyers: "FYERS",
    zerodha: "Zerodha",
    angelone: "Angel One"
};

const statusLabels = {
    success: "Success",
    error: "Error",
    limited: "Rate limited",
    completed: "Completed",
    pending: "Pending",
    expired: "Expired"
};

const periodPresets = {
    "24h": {
        label: "Last 24 hours",
        total: "12,846",
        bars: [38, 52, 44, 67, 56, 83, 72, 93, 77, 100, 69, 84],
        labels: ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"]
    },
    "7d": {
        label: "Last 7 days",
        total: "45,921",
        bars: [48, 63, 51, 72, 65, 89, 76, 100, 69, 82, 93, 74],
        labels: ["Wed", "Thu", "Fri", "Sat", "Sun", "Mon"]
    },
    "30d": {
        label: "Last 30 days",
        total: "184,602",
        bars: [42, 51, 47, 62, 71, 58, 83, 77, 92, 69, 100, 86],
        labels: ["1", "6", "12", "18", "24", "30"]
    }
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) =>
    Array.from(root.querySelectorAll(selector));

function createElement(tag, className, text) {
    const element = document.createElement(tag);

    if (className) {
        element.className = className;
    }

    if (text !== undefined) {
        element.textContent = text;
    }

    return element;
}

function appendCell(row, text, className = "") {
    const cell = createElement("td", className, text);
    row.appendChild(cell);
    return cell;
}

function brokerDisplayName(broker) {
    return brokerNames[broker] || "Unknown";
}

function setBrokerCell(cell, broker) {
    const container = createElement("div", "broker-cell");

    const dot = createElement("span", `broker-dot broker-${broker}`);
    dot.setAttribute("aria-hidden", "true");

    const name = createElement("span", "", brokerDisplayName(broker));

    container.append(dot, name);
    cell.appendChild(container);
}

function makeStatusPill(status) {
    return createElement(
        "span",
        `result-pill ${status}`,
        statusLabels[status] || "Unknown"
    );
}

function renderRequests(rows) {
    const body = $("#requests-body");
    const count = $("#request-count");

    if (!body || !count) {
        return;
    }

    body.replaceChildren();

    if (rows.length === 0) {
        const row = document.createElement("tr");
        const cell = createElement(
            "td",
            "empty-cell",
            "No sample requests match your filters."
        );

        cell.colSpan = 7;
        row.appendChild(cell);
        body.appendChild(row);

        count.textContent = "Showing 0 sample requests";
        return;
    }

    const fragment = document.createDocumentFragment();

    for (const request of rows) {
        const row = document.createElement("tr");

        appendCell(row, request.id, "request-id");
        appendCell(row, request.client, "client-name");

        const brokerCell = document.createElement("td");
        setBrokerCell(brokerCell, request.broker);
        row.appendChild(brokerCell);

        appendCell(row, request.endpoint, "endpoint-cell");
        appendCell(row, request.time, "time-cell");
        appendCell(row, String(request.statusCode), "http-code");

        const statusCell = document.createElement("td");
        statusCell.appendChild(makeStatusPill(request.status));
        row.appendChild(statusCell);

        appendCell(row, request.latency, "time-cell");

        fragment.appendChild(row);
    }

    body.appendChild(fragment);
    count.textContent =
        `Showing ${rows.length} of ${demoRequests.length} sample requests`;
}

function getFilteredRequests() {
    const query = ($("#request-search")?.value || "")
        .trim()
        .toLowerCase();

    const broker = $("#broker-filter")?.value || "all";
    const status = $("#status-filter")?.value || "all";

    return demoRequests.filter(request => {
        const searchable = [
            request.id,
            request.client,
            request.broker,
            brokerDisplayName(request.broker),
            request.endpoint,
            request.time,
            request.statusCode
        ].join(" ").toLowerCase();

        const matchesQuery = searchable.includes(query);
        const matchesBroker = broker === "all" || request.broker === broker;
        const matchesStatus = status === "all" || request.status === status;

        return matchesQuery && matchesBroker && matchesStatus;
    });
}

function renderSessions() {
    const body = $("#sessions-body");

    if (!body) {
        return;
    }

    body.replaceChildren();

    const fragment = document.createDocumentFragment();

    for (const session of demoSessions) {
        const row = document.createElement("tr");

        appendCell(row, session.id, "session-id");

        const brokerCell = document.createElement("td");
        setBrokerCell(brokerCell, session.broker);
        row.appendChild(brokerCell);

        appendCell(row, session.created, "time-cell");
        appendCell(row, session.expires, "time-cell");

        const statusCell = document.createElement("td");
        statusCell.appendChild(makeStatusPill(session.status));
        row.appendChild(statusCell);

        fragment.appendChild(row);
    }

    body.appendChild(fragment);
}

function renderChart(period) {
    const preset = periodPresets[period] || periodPresets["24h"];
    const columns = $$("#chart-columns .chart-column");
    const labels = $$("#chart-x-labels span");

    columns.forEach((column, index) => {
        column.style.setProperty(
            "--height",
            `${preset.bars[index % preset.bars.length]}%`
        );

        column.dataset.label = preset.labels[index % preset.labels.length];
    });

    labels.forEach((label, index) => {
        label.textContent =
            preset.labels[
                Math.round(
                    index * (preset.labels.length - 1) /
                    Math.max(labels.length - 1, 1)
                )
            ];
    });

    const total = $('[data-stat="requests"]');
    if (total) {
        total.textContent = preset.total;
    }

    const periodLabel = $("#chart-period-label");
    if (periodLabel) {
        periodLabel.textContent = preset.label;
    }

    const chart = $("#traffic-chart");
    if (chart) {
        chart.setAttribute(
            "aria-label",
            `Illustrative request chart for ${preset.label.toLowerCase()}`
        );
    }
}

let toastTimeout;

function showToast(message) {
    const toast = $("#toast");

    if (!toast) {
        return;
    }

    window.clearTimeout(toastTimeout);
    toast.textContent = message;
    toast.classList.add("visible");

    toastTimeout = window.setTimeout(() => {
        toast.classList.remove("visible");
    }, 2800);
}

function exportCsv() {
    const rows = getFilteredRequests();

    if (rows.length === 0) {
        showToast("No matching sample rows to export.");
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
        const text = String(value ?? "");

        return `"${text.replace(/"/g, '""')}"`;
    }

    const csv = [
        columns.map(([header]) => escapeCsv(header)).join(","),
        ...rows.map(row =>
            columns.map(([, key]) => escapeCsv(row[key])).join(",")
        )
    ].join("\r\n");

    const blob = new Blob(
        ["\uFEFF", csv],
        { type: "text/csv;charset=utf-8;" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "corex-sample-requests.csv";
    link.style.display = "none";

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);

    showToast(`Exported ${rows.length} sample rows. This is not a live report.`);
}

async function copyEndpoint(path) {
    try {
        await navigator.clipboard.writeText(path);
        showToast(`Copied endpoint path: ${path}`);
    } catch {
        showToast("Clipboard unavailable. Select and copy the endpoint manually.");
    }
}

function setupNavigation() {
    const links = $$(".nav-link[data-nav]");
    const breadcrumb = $("#breadcrumb-current");

    const nameForSection = new Map(
        links.map(link => [link.dataset.nav, link.textContent.trim()])
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
            breadcrumb.textContent = nameForSection.get(id) || "Overview";
        }
    }

    links.forEach(link => {
        link.addEventListener("click", () => {
            setActive(link.dataset.nav);
        });
    });

    if (!("IntersectionObserver" in window)) {
        return;
    }

    const sections = links
        .map(link => document.getElementById(link.dataset.nav))
        .filter(Boolean);

    const observer = new IntersectionObserver(entries => {
        const visible = entries
            .filter(entry => entry.isIntersecting)
            .sort((a, b) => b.intersectionRatio - a.intersectionRatio);

        if (visible.length > 0) {
            setActive(visible[0].target.id);
        }
    }, {
        rootMargin: "-18% 0px -65% 0px",
        threshold: [0, 0.1, 0.25, 0.5]
    });

    sections.forEach(section => observer.observe(section));
}

function setupEvents() {
    $("#request-search")?.addEventListener("input", () => {
        renderRequests(getFilteredRequests());
    });

    $("#broker-filter")?.addEventListener("change", () => {
        renderRequests(getFilteredRequests());
    });

    $("#status-filter")?.addEventListener("change", () => {
        renderRequests(getFilteredRequests());
    });

    $("#export-button")?.addEventListener("click", exportCsv);

    $("#period-select")?.addEventListener("change", event => {
        renderChart(event.target.value);
        showToast("Chart updated using illustrative preview data.");
    });

    $("#refresh-button")?.addEventListener("click", event => {
        const button = event.currentTarget;

        button.classList.remove("is-refreshing");
        void button.offsetWidth;
        button.classList.add("is-refreshing");

        renderRequests(getFilteredRequests());
        renderSessions();

        showToast(
            "Preview refreshed. Live records will appear after database integration."
        );

        window.setTimeout(() => {
            button.classList.remove("is-refreshing");
        }, 700);
    });

    $("#dismiss-notice")?.addEventListener("click", () => {
        const notice = $(".preview-notice");

        if (notice) {
            notice.remove();
        }
    });

    $$(".copy-button[data-copy]").forEach(button => {
        button.addEventListener("click", () => {
            const path = button.dataset.copy;

            if (path) {
                copyEndpoint(path);
            }
        });
    });

    const logoutButton = document.querySelector("#logout-button");

    logoutButton?.addEventListener("click", async () => {
        logoutButton.disabled = true;

        try {
            const response = await fetch("/api/v1/admin/logout", {
                method: "POST",
                credentials: "same-origin"
            });

            if (response.ok) {
                window.location.replace("/login.html");
                return;
            }

            logoutButton.disabled = false;
        } catch {
            logoutButton.disabled = false;
        }
    });
}

async function loadAdminIdentity() {
    const nameElement = $("#profile-name");
    const avatarElement = $("#profile-avatar");
    const profileChip = $("#profile-chip");

    try {
        const response = await fetch("/api/v1/admin/me", {
            method: "GET",
            credentials: "same-origin",
            cache: "no-store"
        });

        if (response.status === 401) {
            window.location.replace("/login.html");
            return;
        }

        if (!response.ok) {
            throw new Error("Unable to load admin identity.");
        }

        const data = await response.json();

        if (
            data.authenticated !== true ||
            typeof data.username !== "string" ||
            !data.username.trim()
        ) {
            throw new Error("Invalid admin identity response.");
        }

        const username = data.username.trim();

        if (nameElement) {
            nameElement.textContent = username;
        }

        if (avatarElement) {
            avatarElement.textContent =
                Array.from(username)[0].toUpperCase();
        }

        if (profileChip) {
            profileChip.title = `Signed in as ${username}`;
        }
    } catch {
        if (nameElement) {
            nameElement.textContent = "Admin";
        }

        if (avatarElement) {
            avatarElement.textContent = "A";
        }
    }
}

function initDashboard() {
    loadAdminIdentity()
    renderRequests(demoRequests);
    renderSessions();
    renderChart($("#period-select")?.value || "24h");
    setupNavigation();
    setupEvents();
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initDashboard, { once: true });
} else {
    initDashboard();
}