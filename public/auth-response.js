"use strict";

const brokers = Object.freeze({
    corex: {
        name: "Broker service",
        mark: "BR",
        badge: "BROKER"
    },

    upstox: {
        name: "Upstox",
        mark: "UP",
        badge: "UPSTOX"
    }
});

const outcomes = Object.freeze({
    received: {
        tone: "success",
        icon: "✓",
        eyebrow: "AUTHORIZATION PROCESSED",
        title: "Authorization received",
        description:
            "Your broker returned successfully and CoreX has securely " +
            "prepared the authentication result.",
        steps: [
            "Return to the CoreX application.",
            "CoreX can now retrieve the authentication result.",
            "Wait for CoreX to confirm that your account is connected."
        ],
        note:
            "This confirms that the broker callback was processed. " +
            "Your connection is fully complete once the CoreX application " +
            "successfully retrieves the result."
    },

    failed: {
        tone: "warning",
        icon: "×",
        eyebrow: "AUTHORIZATION NOT COMPLETED",
        title: "We couldn't complete authorization",
        description:
            "The broker authorization could not be completed. " +
            "This may happen if access was declined or the token exchange failed.",
        steps: [
            "Return to the CoreX application.",
            "Check the connection status.",
            "Start a new authorization attempt if you still want to connect."
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
            "The authorization callback could not be matched to a valid " +
            "CoreX authentication session.",
        steps: [
            "Return to the CoreX application.",
            "Check whether the authorization attempt has expired.",
            "Start a fresh attempt instead of reusing the old callback."
        ],
        note:
            "For your security, detailed callback-validation information " +
            "isn't displayed on this page."
    },

    unavailable: {
        tone: "info",
        icon: "!",
        eyebrow: "TEMPORARY SERVICE ISSUE",
        title: "We couldn't finish processing",
        description:
            "A temporary issue prevented CoreX from finishing the " +
            "authorization process.",
        steps: [
            "Return to the CoreX application and check the connection status.",
            "If the connection did not complete, start a new attempt.",
            "Try again later if the problem persists."
        ],
        note:
            "This page doesn't expose internal errors or credentials. " +
            "Your CoreX application can check the session result separately."
    },

    expired: {
        tone: "warning",
        icon: "⌛",
        eyebrow: "AUTHORIZATION EXPIRED",
        title: "This attempt has expired",
        description:
            "The authentication session is no longer valid, so CoreX " +
            "cannot use it to finish connecting your account.",
        steps: [
            "Return to the CoreX application.",
            "Start a new authorization attempt.",
            "Complete broker authorization before the new session expires."
        ],
        note:
            "Authorization codes and session credentials must not be reused " +
            "after expiration."
    }
});

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

    setText("status-note", outcome.note);

    renderSteps(outcome.steps);

    document.title = `${outcome.title} | CoreX`;
}

renderResponse();