import express from "express";

export function createApp(env) {
    const app = express();

    app.disable("x-powered-by");

    // All API responses must not be cached.
    app.use((_req, res, next) => {
        res.set("Cache-Control", "no-store");
        next();
    });

    // Broker credentials will have a 1 KB limit in the V3 API.
    // Keep the overall JSON request body small as well.
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

    // Unknown API routes must return JSON.
    app.use("/api", (_req, res) => {
        return res.status(404).json({
            error: "not_found",
            message: "The requested API endpoint was not found."
        });
    });

    // Non-API fallback.
    app.use((_req, res) => {
        return res.status(404).type("text/plain").send("Not found.");
    });

    return app;
}