import { Router } from "express";
import {
    createAuthSessionV2,
    getAuthSessionResultV2
} from "../services/auth-sessions-v2.service.js";
import { requireCorexClient } from "../middleware/require-corex-client.js";
import { limitSessionCreation, limitSessionPolling } from "../middleware/rate-limits.js";
import { BROKER_IDS } from "../providers/provider-registry.js";

const FIELD_MAX_LENGTH = { broker: 32, appId: 200, appSecret: 512, clientPublicKey: 128 };

const FIELD_HELP = {
    appId: "must be the broker app's API key / client id.",
    appSecret: "must be the broker app's API secret.",
    clientPublicKey:
        "must be the base64url raw P-256 public key printed by `node tools/keygen.mjs` " +
        "(copy it exactly, with no spaces or line breaks)."
};

// Error bodies name the field only. They never echo a submitted value.
function badRequest(res, field, message) {
    return res.status(400).json({ error: "invalid_request", field, message });
}

/** Returns an error description for the first bad field, or null. */
function findInvalidField(body) {
    if (!body || typeof body !== "object" || Array.isArray(body)) {
        return { field: null, message: "Body must be a JSON object. Send Content-Type: application/json." };
    }

    for (const [field, max] of Object.entries(FIELD_MAX_LENGTH)) {
        const value = body[field];

        if (typeof value !== "string" || value.trim().length === 0) {
            return { field, message: `"${field}" is required and must be a non-empty string.` };
        }
        if (value.length > max) {
            return { field, message: `"${field}" is too long (max ${max} characters).` };
        }
        if (/\{\{.*\}\}/.test(value)) {
            return {
                field,
                message: `"${field}" still contains a {{placeholder}}. Select your Postman environment and fill in that variable.`
            };
        }
    }

    return null;
}

export default function createAuthV2Router(env) {
    const router = Router();

    router.use((_req, res, next) => {
        res.set("Cache-Control", "no-store");
        next();
    });

    router.post("/sessions", requireCorexClient(env), limitSessionCreation(env), async (req, res) => {
        const invalid = findInvalidField(req.body);

        if (invalid) {
            return badRequest(res, invalid.field, invalid.message);
        }

        const { broker, appId, appSecret, clientPublicKey } = req.body;

        try {
            const session = await createAuthSessionV2(env, {
                broker: broker.trim().toLowerCase(),
                appId: appId.trim(),
                appSecret,
                clientPublicKey: clientPublicKey.trim(),
                corexClientId: req.corexClient.id
            });

            return res.status(201).json(session);
        } catch (error) {
            // Never log the request body, secrets, state or URLs.
            if (error.code === "UNSUPPORTED_BROKER") {
                return res.status(400).json({
                    error: "unsupported_broker",
                    message: `Supported brokers: ${BROKER_IDS.join(", ")}.`
                });
            }
            if (error.code === "INVALID_REQUEST") {
                return badRequest(
                    res,
                    error.field ?? null,
                    `"${error.field}" ${FIELD_HELP[error.field] ?? "is invalid."}`
                );
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
