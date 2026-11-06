import { Router } from "express";

import { requireClientAuth } from "../../gateway/client-auth.js";
import { sendApiError } from "../../gateway/errors.js";
import { createAuthSession } from "./auth.service.js";

const ERROR_MESSAGES = {
    invalid_request: "The request contains invalid data.",
    unsupported_broker: "The requested broker is not supported.",
    payload_too_large: "The credentials object exceeds the 1 KB limit.",
    unauthorized: "A valid active CoreX client is required.",
    rate_limit_exceeded: "Too many authentication sessions were created.",
    too_many_sessions: "The client already has five unfinished sessions."
};

export default function createAuthRouter(env) {
    const router = Router();

    router.post(
        "/sessions",
        requireClientAuth(env, "auth"),
        async (req, res) => {
            const result = await createAuthSession(env, {
                clientId: req.corexClient.id,
                body: req.body
            });

            if (result.error) {
                if (result.retryAfter) {
                    res.set(
                        "Retry-After",
                        String(result.retryAfter)
                    );
                }

                return sendApiError(
                    res,
                    result.httpStatus,
                    result.error,
                    ERROR_MESSAGES[result.error],
                    result.field
                );
            }

            return res.status(201).json(result);
        }
    );

    return router;
}