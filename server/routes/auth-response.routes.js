import { Router } from "express";

const ALLOWED_BROKERS = new Set([
    "upstox",
    "fyers",
    "zerodha",
    "angelone",
    "angel-one"
]);

const ALLOWED_STATUSES = new Set([
    "received",
    "failed",
    "invalid",
    "unavailable",
    "expired"
]);

function normalizeBroker(value) {
    if (typeof value !== "string") {
        return "corex";
    }

    const broker = value.trim().toLowerCase();

    return ALLOWED_BROKERS.has(broker)
        ? broker
        : "corex";
}

function normalizeStatus(value) {
    if (typeof value !== "string") {
        return "invalid";
    }

    const status = value.trim().toLowerCase();

    return ALLOWED_STATUSES.has(status)
        ? status
        : "invalid";
}

function protectResponse(res) {
    res.set({
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy":
            "default-src 'none'; " +
            "script-src 'self'; " +
            "style-src 'self'; " +
            "img-src 'self'; " +
            "base-uri 'none'; " +
            "form-action 'none'; " +
            "frame-ancestors 'none'; " +
            "object-src 'none'"
    });
}

export default function createAuthResponseRouter(env) {
    const router = Router();

    router.get("/response", async (req, res) => {
        protectResponse(res);

        const broker = normalizeBroker(req.query.broker);
        const status = normalizeStatus(req.query.status);

        if (!env.ASSETS) {
            return res
                .status(503)
                .type("text")
                .send("CoreX authorization page is unavailable.");
        }

        try {
            const assetResponse = await env.ASSETS.fetch(
                "https://assets.local/auth-response.html"
            );

            if (!assetResponse.ok) {
                throw new Error("Authorization page asset was not found");
            }

            let html = await assetResponse.text();

            // Only allowlisted values are inserted into HTML attributes.
            html = html
                .replace("__COREX_BROKER__", broker)
                .replace("__COREX_STATUS__", status);

            return res
                .status(200)
                .type("html")
                .send(html);
        } catch (error) {
            console.error(
                "Authorization response page failed:",
                error instanceof Error ? error.message : "Unknown error"
            );

            return res
                .status(503)
                .type("text")
                .send("CoreX authorization page is temporarily unavailable.");
        }
    });

    return router;
}