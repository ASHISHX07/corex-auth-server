import { Router } from "express";
import { createAuthSession, getAuthSessionResult } from "../services/auth-sessions.service.js";
import { requireCorexClient } from "../middleware/require-corex-client.js";
import { limitSessionCreation } from "../middleware/rate-limits.js";

export default function createAuthRouter(env) {
    const router = Router();

    router.post("/sessions", requireCorexClient(env), limitSessionCreation(env), async (req, res) => {
        const broker = req.body?.broker;
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
                appId: appId.trim(),
                corexClientId: req.corexClient.id
            });

            return res.status(201).json(session);
        } catch (error) {
            // Do not log state, secrets, codes or full URLs.
            if (error.code === "UNSUPPORTED_BROKER") {
                return res.status(400).json({
                    error: "unsupported_broker"
                });
            }

            console.error(
                "Session creation failed:",
                error instanceof Error ? error.message : "Unknown error"
            );

            return res.status(500).json({
                error: "session_creation_failed"
            });
        }
    });

    router.get("/sessions/:sessionId/result", async (req, res) => {
        const authorization = req.get("authorization") ?? "";
        const match = /^Bearer ([A-Za-z0-9_-]{40,100})$/.exec(authorization);
    
        if (!match) {
            return res.status(401).json({
                error: "missing_retrieval_credential"
            });
        }
    
        try {
            const result = await getAuthSessionResult(env, {
                sessionId: req.params.sessionId,
                retrievalSecret: match[1]
            });
    
            switch (result.status) {
                case "not_found":
                    return res.status(404).json({
                        error: "session_not_found"
                    });
    
                case "pending":
                    return res.status(202).json(result);
    
                case "completed":
                    return res.status(200).json(result);
    
                case "failed":
                    return res.status(409).json(result);
    
                case "expired":
                case "already_retrieved":
                    return res.status(410).json(result);
    
                default:
                    return res.status(409).json(result);
            }
        } catch (error) {
            console.error(
                "Result retrieval failed:",
                error instanceof Error ? error.message : "Unknown error"
            );
    
            return res.status(500).json({
                error: "result_retrieval_failed"
            });
        }
    });

    return router;
}