import { Router } from "express";
import { createAuthSession } from "../services/auth-sessions.service.js";

export default function createAuthRouter(env) {
    const router = Router();

    router.post("/sessions", async (req, res) => {
        const clientId = req.body?.clientId;

        if (
            typeof clientId !== "string" ||
            clientId.trim().length === 0 ||
            clientId.length > 200
        ) {
            return res.status(400).json({
                error: "invalid client id"
            });
        }

        try {
            const session = await createAuthSession(env, clientId.trim());
            return res.status(201).json(session);
        } catch {
            // Do not log state, secrets, codes or full URLs.
            return res.status(500).json({
                error: "session creation failed"
            });
        }
    });

    return router;
}