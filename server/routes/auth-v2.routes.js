import { Router } from "express";
import {
    createAuthSessionV2,
    getAuthSessionResultV2
} from "../services/auth-sessions-v2.service.js";
import { requireCorexClient } from "../middleware/require-corex-client.js";
import { limitSessionCreation, limitSessionPolling } from "../middleware/rate-limits.js";

const isString = (value, max) =>
    typeof value === "string" && value.length > 0 && value.length <= max;

export default function createAuthV2Router(env) {
    const router = Router();

    router.use((_req, res, next) => {
        res.set("Cache-Control", "no-store");
        next();
    });

    router.post("/sessions", requireCorexClient(env), limitSessionCreation(env), async (req, res) => {
        const { broker, appId, appSecret, clientPublicKey } = req.body ?? {};

        if (
            !isString(broker, 32) || !isString(appId, 200) ||
            !isString(appSecret, 512) || !isString(clientPublicKey, 128)
        ) {
            return res.status(400).json({ error: "invalid_request" });
        }

        try {
            const session = await createAuthSessionV2(env, {
                broker: broker.trim().toLowerCase(),
                appId: appId.trim(),
                appSecret,
                clientPublicKey,
                corexClientId: req.corexClient.id
            });

            return res.status(201).json(session);
        } catch (error) {
            // Never log the request body, secrets, state or URLs.
            if (error.code === "UNSUPPORTED_BROKER") {
                return res.status(400).json({ error: "unsupported_broker" });
            }
            if (error.code === "INVALID_REQUEST") {
                return res.status(400).json({ error: "invalid_request" });
            }

            console.error("Session creation failed:", error instanceof Error ? error.message : "Unknown error");
            return res.status(500).json({ error: "session_creation_failed" });
        }
    });

    router.get("/sessions/:sessionId/result", requireCorexClient(env), limitSessionPolling(env), async (req, res) => {
        try {
            const result = await getAuthSessionResultV2(env, {
                sessionId: req.params.sessionId,
                corexClientId: req.corexClient.id
            });

            const httpStatus = {
                not_found: 404,
                pending: 202,
                completed: 200,
                failed: 409,
                expired: 410,
                already_retrieved: 410
            }[result.status] ?? 409;

            return res.status(httpStatus).json(
                result.status === "not_found" ? { error: "session_not_found" } : result
            );
        } catch (error) {
            console.error("Result retrieval failed:", error instanceof Error ? error.message : "Unknown error");
            return res.status(500).json({ error: "result_retrieval_failed" });
        }
    });

    return router;
}
