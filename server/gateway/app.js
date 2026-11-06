import express from "express";

import { requestId } from "./request-id.js";
import {
    sendApiError,
    notFoundHandler,
    apiErrorHandler
} from "./errors.js";
import createAuthRouter from "../modules/auth/auth.routes.js";
import createAuthCallbackRouter from "../modules/auth/callback.routes.js";

export function createApp(env) {
    const app = express();

    app.disable("x-powered-by");

    // Common response headers and request identity.
    app.use(requestId);

    app.use((_req, res, next) => {
        res.set("Cache-Control", "no-store");
        next();
    });

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

    app.use(notFoundHandler);
    app.use(apiErrorHandler);

    return app;
}