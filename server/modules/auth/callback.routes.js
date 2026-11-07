import { Router } from "express";

import { rateLimit } from "../../gateway/rate-limits.js";
import { completeAuthCallback } from "./auth.service.js";
import { BROKER_IDS } from "../../brokers/registry.js";

const ALLOWED_STATUSES = new Set([
    "received",
    "failed",
    "invalid",
    "unavailable",
    "expired"
]);

function normalizeStatus(value) {
    if (typeof value !== "string") {
        return "invalid";
    }

    const status = value.trim().toLowerCase();

    return ALLOWED_STATUSES.has(status)
        ? status
        : "invalid";
}

function normalizeBroker(value) {
    if (typeof value !== "string") {
        return "corex";
    }

    const broker = value.trim().toLowerCase();

    return BROKER_IDS.includes(broker)
        ? broker
        : "corex";
}

function setBrowserSecurityHeaders(res) {
    res.set({
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-Robots-Tag": "noindex, nofollow",
        "Permissions-Policy":
            "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy":
            "default-src 'none'; " +
            "script-src 'self'; " +
            "style-src 'self'; " +
            "img-src 'self'; " +
            "font-src 'self'; " +
            "connect-src 'none'; " +
            "object-src 'none'; " +
            "base-uri 'none'; " +
            "form-action 'none'; " +
            "frame-ancestors 'none'"
    });
}

function redirectToStatus(res, broker, status) {
    const params = new URLSearchParams({
        broker: normalizeBroker(broker),
        status: normalizeStatus(status)
    });

    setBrowserSecurityHeaders(res);

    return res.redirect(
        303,
        `/auth/response?${params.toString()}`
    );
}

async function sendAuthResponsePage(env, req, res, {
    broker,
    status
}) {
    if (typeof env?.ASSETS?.fetch !== "function") {
        return res
            .status(503)
            .type("text")
            .send("CoreX authorization page is unavailable.");
    }

    try {
        const assetResponse = await env.ASSETS.fetch(
            new Request("https://assets.local/auth-response.html")
        );

        if (!assetResponse.ok) {
            throw new Error("Authorization page asset unavailable.");
        }

        let html = await assetResponse.text();

        // Values are normalized against fixed allowlists before insertion.
        html = html
            .replaceAll("__COREX_BROKER__", broker)
            .replaceAll("__COREX_STATUS__", status);

        return res
            .status(200)
            .type("html")
            .send(html);
    } catch (error) {
        console.error("Authorization response page failed", {
            requestId: req.requestId,
            errorName: error instanceof Error
                ? error.name
                : "UnknownError"
        });

        return res
            .status(503)
            .type("text")
            .send("CoreX authorization page is temporarily unavailable.");
    }
}

export default function createAuthCallbackRouter(env) {
    const router = Router();

    // Generic public authorization status page.
    router.get("/response", async (req, res) => {
        setBrowserSecurityHeaders(res);

        return sendAuthResponsePage(env, req, res, {
            broker: normalizeBroker(req.query.broker),
            status: normalizeStatus(req.query.status)
        });
    });

    // Public broker redirect target.
    router.get(
        "/:broker/callback",

        rateLimit(
            env,
            "CALLBACK_LIMITER",
            req => {
                const ip = req.get("cf-connecting-ip") || "unknown";

                return `${req.params.broker}:${ip}`;
            }
        ),

        async (req, res) => {
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

            return redirectToStatus(
                res,
                req.params.broker,
                status
            );
        }
    );

    return router;
}