"use strict";

/* CoreX Admin Console — live D1-backed data. */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) =>
    Array.from(root.querySelectorAll(selector));

const state = {
    overview: null,
    requests: [],
    sessions: [],
    clients: []
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
        setText