import { Router } from "express";

import { requireClientAuth } from "../../gateway/client-auth.js";
import { sendApiError } from "../../gateway/errors.js";
import { createAuthSession, getAuthSessionResult } from "./auth.service.js";

const ERROR_MESSAGES = {
    invalid_request: "The request contains invalid data.",
    unsupported_broker: "The requested broker is not supported.",
    payload_too_large: "The credentials object exceeds the 1 KB limit.",
    unauthorized: "A valid active CoreX client is required.",
    rate_limit_exceeded: "Too many authentication sessions were created.",
    too_many_sessions: "The client already has five unfinished sessions.",
    session_not_found: "The requested session was not found.",
    expired: "The authentication session has expired.",
    cancelled: "The authentication session was cancelled.",
    already_retrieved: "The authentication result has already been retrieved.",
    authorization_denied: "Broker authorization was denied.",
    exchange_rejected: "The broker rejected the token exchange.",
    provider_unreachable: "The broker could not be reached.",
    provider_unavailable: "The broker is temporarily unavailable.",
    provider_bad_response: "The broker returned an invalid response.",
    service_unavailable: "Authentication is temporarily unavailable.",
    authentication_failed: "Authentication could not be completed."
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

    router.post(
        "/sessions/:sessionId/result",
        requireClientAuth(env, "auth"),
        async (req, res) => {
            const result = await getAuthSessionResult(env, {
                sessionId: req.params.sessionId,
                clientId: req.corexClient.id
            });

            if (result.error) {
                return sendApiError(
                    res,
                    result.httpStatus,
                    result.error,
                    ERROR_MESSAGES[result.error]
                );
            }

            if (result.status === "pending") {
                res.set("Retry-After", "3");

                return res.status(202).json({
                    status: "pending"
                });
            }

            return res.status(200).json(result);
        }
    );

    return router;
}