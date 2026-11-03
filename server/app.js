import express from "express";

import healthRouter from "./routes/health.routes.js";
import createAuthRouter from "./routes/auth.routes.js";
import createAuthResponseRouter from "./routes/auth-response.routes.js";
import createAuthV2Router from "./routes/auth-v2.routes.js";
import createBrokerCallbackRouter from "./routes/callbacks/broker-callback.routes.js";
import createAdminRouter from "./routes/admin.routes.js";
import { requestLogger } from "./middleware/request-logger.js";
import {
    readAdminSessionCookie,
    verifyAdminSessionToken
} from "./security/admin-session.js";

export function createApp(env) {
    const app = express();

    app.disable("x-powered-by");

    app.use(express.json({
        limit: "16kb",
        strict: true,
        type: "application/json"
    }));

    app.use(requestLogger(env));
    app.use("/api/health", healthRouter);
    app.use("/api/v1/auth", createAuthRouter(env)); // deprecated: client exchanges the code itself
    app.use("/api/v2/auth", createAuthV2Router(env));
    app.use("/api/v1/admin", createAdminRouter(env));

    // Shared browser-facing authorization page.
    app.use("/auth", createAuthResponseRouter(env));

    // Callback for every registered broker: /auth/:broker/callback
    app.use("/auth/:broker", createBrokerCallbackRouter(env));

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

                return await sendAssetHtml(env, "index.html", res);
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

            return await sendAssetHtml(env, "login.html", res);
        } catch {
            return res.status(503).send(
                "Login is temporarily unavailable."
            );
        }
    });

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