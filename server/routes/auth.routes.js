import { Router } from "express";
import { createAuthSession } from "../services/auth-sessions.service.js";

export default function createAuthRouter(env) {
    const router = Router();

    router.post("/sessions", async (req, res) => {
        const clientId = req.body?.clientId;
        const appId = req.body?.appId;

        if (
            typeof broker !== "string" ||
            broker.trim().length === 0 ||
            typeof appId !== "string" ||
            appId.trim().length === 0 ||
            appId.length > 200
        ) {
            return res.status(400).json({
                error: "invalid_request"
            });
        }

        try {
            const session = await createAuthSession(env, {
                broker: broker.trim().toLowerCase(),
                appId: appId.trim()
            });

            return res.status(201).json(session);
        } catch (error) {
            // Do not log state, secrets, codes or full URLs.
            if (error.code === "UNSUPPORTED_BROKER") {
                return res.status(400).json({
                    error: "unsupported_broker"
                });
            }

            return res.status(500).json({
                error: "session_creation_failed"
            });
        }
    });

    return router;
}