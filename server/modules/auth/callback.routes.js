import { Router } from "express";

import { completeAuthCallback } from "./auth.service.js";

const STATUS_MESSAGES = Object.freeze({
    received:
        "Authorization was received successfully. You can return to CoreX.",
    failed:
        "Broker authorization could not be completed. Start a new session in CoreX.",
    invalid:
        "This authorization link is invalid or has already been used.",
    expired:
        "This authentication session has expired. Start a new session in CoreX.",
    unavailable:
        "Authentication is temporarily unavailable. Try again from CoreX."
});

function setBrowserSecurityHeaders(res) {
    res.set({
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy":
            "default-src 'none'; " +
            "base-uri 'none'; " +
            "form-action 'none'; " +
            "frame-ancestors 'none'"
    });
}

function redirectToStatus(res, status) {
    const safeStatus = Object.hasOwn(STATUS_MESSAGES, status)
        ? status
        : "invalid";

    setBrowserSecurityHeaders(res);

    return res.redirect(
        303,
        `/auth/response?status=${safeStatus}`
    );
}

export default function createAuthCallbackRouter(env) {
    const router = Router();

    // Public, human-readable result page.
    router.get("/response", (req, res) => {
        setBrowserSecurityHeaders(res);

        const status = typeof req.query.status === "string"
            ? req.query.status
            : "invalid";

        const message = STATUS_MESSAGES[status] ??
            STATUS_MESSAGES.invalid;

        return res
            .status(200)
            .type("html")
            .send(`<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CoreX Authorization</title>
</head>
<body>
    <main>
        <h1>CoreX Authorization</h1>
        <p>${message}</p>
    </main>
</body>
</html>`);
    });

    // Public broker redirect target.
    router.get("/:broker/callback", async (req, res) => {
        let status = "unavailable";

        try {
            status = await completeAuthCallback(env, {
                broker: req.params.broker,
                state: req.query.state,
                query: req.query
            });
        } catch (error) {
            // Never log the callback URL, authorization code,
            // OAuth state, credentials or provider response.
            console.error("Broker callback failed", {
                requestId: req.requestId,
                errorName: error instanceof Error
                    ? error.name
                    : "UnknownError"
            });
        }

        return redirectToStatus(res, status);
    });

    return router;
}