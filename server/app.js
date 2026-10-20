import express from "express";
import healthRouter from "./routes/health.routes.js";
import authRouter from "./routes/auth.routes.js";

export function createApp(_env) {
    const app = express();

    app.disable("x-powered-by");

    app.use(express.json({
        limit: "16kb",
        strict: true,
        type: "application/json"
    }));

    app.use("/api/health", healthRouter);
    app.use("/auth/getAuthCode", authRouter);
    
    return app;
}