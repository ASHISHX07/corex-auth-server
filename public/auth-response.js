"use strict";

const brokers = {
    corex: {
        name: "Your broker",
        mark: "BR",
        badge: "BROKER"
    },

    upstox: {
        name: "Upstox",
        mark: "UP",
        badge: "UPSTOX"
    },

    fyers: {
        name: "FYERS",
        mark: "FY",
        badge: "FYERS"
    },

    zerodha: {
        name: "Zerodha",
        mark: "ZE",
        badge: "ZERODHA"
    },

    angelone: {
        name: "Angel One",
        mark: "A1",
        badge: "ANGEL ONE"
    },

    "angel-one": {
        name: "Angel One",
        mark: "A1",
        badge: "ANGEL ONE"
    }
};

const outcomes = {
    received: {
        tone: "success",
        icon: "✓",
        eyebrow: "AUTHORIZATION CODE RECEIVED",
        title: "You're almost connected",
        description:
            "Your broker returned an authorization response. " +
            "you can close this tab and continue to CoreX app",
        steps: [
            "Return to the CoreX application.",
            "CoreX will securely retrieve the authorization result.",
            "CoreX will finish the token exchange and confirm the connection."
        ],
        note:
            "The authorization response was received, but this page alone " +
            "does not confirm that your account is fully connected."
    },

    failed: {
        tone: "warning",
        icon: "×",
        eyebrow: "AUTHORIZATION NOT COMPLETED",
        title: "Authorization was cancelled",
        description:
            "The authorization process was not completed. This may happen " +
            "when you cancel the login or decline the requested permissions.",
        steps: [
            "Return to the CoreX application.",
            "Check the connection status.",
            "If you still want to connect your account, start a new authorization attempt."
        ],
        note:
            "No successful connection should be assumed from this response. " +
            "You can safely start again from CoreX."
    },

    invalid: {
        tone: "error",
        icon: "!",
        eyebrow: "REQUEST NOT VERIFIED",
        title: "We couldn't verify this request",
        description:
            "The callback could not be matched to a valid authorization session. " +
            "The request may be invalid, expired, or already used.",
        steps: [
            "Return to the CoreX application.",
            "Check whether the authorization attempt has expired.",
            "Start a fresh attempt instead of reusing the old callback."
        ],
        note:
            "For your security, CoreX does not reveal detailed callback-validation information on this page."
    },

    unavailable: {
        tone: "info",
        icon: "!",
        eyebrow: "TEMPORARY SERVICE ISSUE",
        title: "We couldn't finish processing",
        description:
            "CoreX encountered a temporary problem while processing the authorization response.",
        steps: [
            "Return to the CoreX application and check the connection status.",
            "If the connection did not complete, start a new authorization attempt.",
            "If this keeps happening, try again later."
        ],
        note:
            "This page doesn't expose internal server errors or credentials. Your application can check the session result separately."
    },

    expired: {
        tone: "warning",
        icon: "⌛",
        eyebrow: "AUTHORIZATION EXPIRED",
        title: "This attempt has expired",
        description:
            "The authorization session is no longer valid, so CoreX cannot use it to finish connecting your account.",
        steps: [
            "Return to the CoreX application.",
            "Start a new authorization attempt.",
            "Complete the broker login before the new session expires."
        ],
        note:
            "Authorization codes and session credentials should not be reused after expiration."
    }
};

const root = document.documentElement;

const brokerKey = root.dataset.corexBroker || "corex";
const statusKey = root.dataset.corexStatus || "invalid";

const broker = brokers[brokerKey] || brokers.corex;
const outcome = outcomes[statusKey] || outcomes.invalid;

function setText(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.textContent = value;
    }
}

function renderSteps(steps) {
    const list = document.getElementById("steps-list");

    if (!list) {
        return;
    }

    list.replaceChildren();

    for (const step of steps) {
        const item = document.createElement("li");
        item.textContent = step;
        list.appendChild(item);
    }
}

function renderResponse() {
    const card = document.getElementById("response-card");

    if (card) {
        card.dataset.tone = outcome.tone;
    }

    setText("status-icon", outcome.icon);
    setText("status-eyebrow", outcome.eyebrow);
    setText("status-title", outcome.title);
    setText("status-description", outcome.description);

    setText("broker-name", broker.name);
    setText("broker-mark", broker.mark);
    setText("broker-badge", broker.badge);

    setText("steps-title", "What happens next");

    const note = document.querySelector("#status-note p");
    if (note) {
        note.textContent = outcome.note;
    }

    renderSteps(outcome.steps);

    document.title = `${outcome.title} | CoreX`;
}

renderResponse();