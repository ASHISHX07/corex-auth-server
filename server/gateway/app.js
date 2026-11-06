import express from "express";

import healthRouter from "../routes/health.routes.js";
import createAuthRouter from "../routes/auth.routes.js";
import createAuthResponseRouter from "../routes/auth-response.routes.js";
import createAuthV2Router from "../routes/auth-v2.routes.js";
import createBrokerCallbackRouter from "../routes/callbacks/broker-callback.routes.js";
import createAdminRouter from "../routes/admin.routes.js";

import { requestId } from "./request-id.js";
import { requestLogger } from "./request-logger.js";
import {
    notFoundHandler,
    apiErrorHandler
} from "./errors.js";

import {
    readAdminSessionCookie,
    verifyAdminSessionToken
} from "../security/admin-session.js";

export function createApp(env) {
    const app = express();

    app.disable("x-powered-by");

    // Shared response identity and cache policy.
    app.use(requestId);

    app.use((_req, res, next) => {
        res.set("Cache-Control", "no-store");
        next();
    });

    // Register logging before body parsing so parser failures are logged too.
    app.use(requestLogger(env));

    app.use(express.json({
        limit: "16kb",
        strict: true,
        type: "application/json"
    }));

    // API routes.
    app.use("/api/health", healthRouter);
    app.use("/api/v1/auth", createAuthRouter(env));
    app.use("/api/v2/auth", createAuthV2Router(env));
    app.use("/api/v1/admin", createAdminRouter(env));

    // Browser-facing authorization and broker callback routes.
    app.use("/auth", createAuthResponseRouter(env));
    app.use("/auth/:broker", createBrokerCallbackRouter(env));

    // Protected dashboard.
    app.get(
        ["/", "/index.html", "/dashboard.html"],
        async (req, res) => {
            setDashboardSecurityHeaders(res);

            try {
                const token = readAdminSessionCookie(req);

                const claims = token
                    ? await verifyAdminSessionToken(env, token)
                    : null;

                if (!claims) {
                    return res.redirect(303, "/login.html");
                }

                return await sendAssetHtml(
                    env,
                    "index.html",
                    res
                );
            } catch {
                return res.status(503).send(
                    "Dashboard authentication is unavailable."
                );
            }
        }
    );

    app.get("/login.html", async (req, res) => {
        setDashboardSecurityHeaders(res);

        try {
            const token = readAdminSessionCookie(req);

            const claims = token
                ? await verifyAdminSessionToken(env, token)
                : null;

            if (claims) {
                return res.redirect(303, "/");
            }

            return await sendAssetHtml(
                env,
                "login.html",
                res
            );
        } catch {
            return res.status(503).send(
                "Login is temporarily unavailable."
            );
        }
    });

    // Unknown routes and errors.
    app.use(notFoundHandler);
    app.use(apiErrorHandler);

    return app;
}

function setDashboardSecurityHeaders(res) {
    res.set({
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy":
            "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; " +
            "connect-src 'self'; " +
            "font-src 'self'; " +
            "object-src 'none'; " +
            "base-uri 'self'; " +
            "frame-ancestors 'none'; " +
            "form-action 'self'"
    });
}

async function sendAssetHtml(env, assetName, res) {
    const response = await env.ASSETS.fetch(
        new Request(`https://assets.local/${assetName}`)
    );

    if (!response.ok) {
        return res.status(404).send("Page not found.");
    }

    res.status(response.status);
    res.type("html");

    return res.send(await response.text());
}
