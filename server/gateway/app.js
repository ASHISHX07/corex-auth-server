import express from "express";
import { requestLogger } from "./request-logger.js";
import { requestId } from "./request-id.js";
import {
    sendApiError,
    notFoundHandler,
    apiErrorHandler
} from "./errors.js";
import createAuthRouter from "../modules/auth/auth.routes.js";
import createAuthCallbackRouter from "../modules/auth/callback.routes.js";
import createAdminRouter from "../admin/admin.routes.js";
import {
    readAdminSessionCookie,
    verifyAdminSessionToken
} from "../security/admin-session.js";

function setAdminPageSecurityHeaders(res) {
    res.set({
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-Robots-Tag": "noindex, nofollow",
        "Content-Security-Policy":
            "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self'; " +
            "img-src 'self' data:; " +
            "connect-src 'self'; " +
            "font-src 'self'; " +
            "object-src 'none'; " +
            "base-uri 'self'; " +
            "frame-ancestors 'none'; " +
            "form-action 'self'"
    });
}

async function sendAdminHtml(env, filename, res) {
    if (typeof env?.ASSETS?.fetch !== "function") {
        return res.status(503).type("text").send(
            "Static assets are not configured."
        );
    }

    const response = await env.ASSETS.fetch(
        new Request(`https://assets.local/${filename}`)
    );

    if (!response.ok) {
        return res.status(404).type("text").send("Page not found.");
    }

    return res
        .status(response.status)
        .type("html")
        .send(await response.text());
}

export function createApp(env, waitUntil) {
    const app = express();

    app.disable("x-powered-by");

    // Common response headers and request identity.
    app.use(requestId);

    app.use((_req, res, next) => {
        res.set("Cache-Control", "no-store");
        next();
    });

    app.use(requestLogger(env, waitUntil));

    // API requests containing a body must use JSON.
    app.use("/api", (req, res, next) => {
        const hasBody =
            Number(req.get("content-length") || 0) > 0 ||
            Boolean(req.get("transfer-encoding"));

        if (hasBody && !req.is("application/json")) {
            return sendApiError(
                res,
                415,
                "unsupported_media_type",
                "Requests with a body must use application/json."
            );
        }

        next();
    });

    app.use(express.json({
        limit: "2kb",
        strict: true
    }));

    // Public health endpoint.
    app.get("/api/health", (_req, res) => {
        return res.status(200).json({
            status: "ok"
        });
    });

    // V3 authentication module.
    app.use("/api/v3/auth", createAuthRouter(env));

    // Public broker callbacks and authorization status page.
    app.use("/auth", createAuthCallbackRouter(env));

    // Private administrator module.
    app.use("/api/v3/admin", createAdminRouter(env));

    // Protected administrator pages.
    app.get(
        ["/", "/index.html", "/dashboard.html"],
        async (req, res) => {
            setAdminPageSecurityHeaders(res);

            try {
                const token = readAdminSessionCookie(req);

                const claims = token
                    ? await verifyAdminSessionToken(env, token)
                    : null;

                if (!claims) {
                    return res.redirect(303, "/login.html");
                }

                return await sendAdminHtml(env, "index.html", res);
            } catch {
                console.error("Dashboard access failed", {
                    requestId: req.requestId
                });

                return res.status(503).type("text").send(
                    "Dashboard authentication is temporarily unavailable."
                );
            }
        }
    );

    // Login page redirects already-authenticated administrators.
    app.get("/login.html", async (req, res) => {
        setAdminPageSecurityHeaders(res);

        try {
            const token = readAdminSessionCookie(req);

            const claims = token
                ? await verifyAdminSessionToken(env, token)
                : null;

            if (claims) {
                return res.redirect(303, "/");
            }

            return await sendAdminHtml(env, "login.html", res);
        } catch {
            return res.status(503).type("text").send(
                "Login is temporarily unavailable."
            );
        }
    });

    app.use(notFoundHandler);
    app.use(apiErrorHandler);

    return app;
}

