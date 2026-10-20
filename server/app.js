import express from "express";
import healthRouter from "./routes/health.routes.js";
import createAuthRouter from "./routes/auth.routes.js";
import createUpstoxCallbackRouter from "./routes/callbacks/upstox.routes.js";

export function createApp(env) {
    const app = express();

    app.disable("x-powered-by");

    app.use(express.json({
        limit: "16kb",
        strict: true,
        type: "application/json"
    }));

    app.use("/api/health", healthRouter);
    app.use("/api/v1/auth", createAuthRouter(env));
    app.use("/auth/upstox", createUpstoxCallbackRouter(env));
    
    return app;
}