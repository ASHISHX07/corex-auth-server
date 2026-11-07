import { Router } from "express";

import {
    isSameOriginRequest,
    requireSameOrigin,
    requireAdmin
} from "./admin-auth.js";

import { rateLimit } from "../gateway/rate-limits.js";
import { sendApiError } from "../gateway/errors.js";

import {
    verifyAdminCredentials
} from "../security/admin-credentials.js";

import {
    createAdminSessionToken,
    setAdminSessionCookie,
    clearAdminSessionCookie,
    SESSION_TTL_SECONDS
} from "../security/admin-session.js";

import {
    createCorexClient,
    getCorexClients,
    getCorexClient,
    updateCorexClientScopes,
    revokeCorexClient,
    getAdminAudit
} from "./admin.service.js";

const ERROR_MESSAGES = {
    invalid_request: "The request contains invalid data.",
    unauthorized: "Administrator authentication is required.",
    cross_origin: "Cross-origin request rejected.",
    client_not_found: "The requested CoreX client was not found.",
    invalid_client_id: "The client ID is invalid.",
    invalid_scopes: "The requested client scopes are invalid.",
    admin_operation_failed: "The administrator operation failed."
};

function validId(value) {
    return (
        typeof value === "string" &&
        value.length > 0 &&
        value.length <= 128
    );
}

function sendInternalError(res, req, operation) {
    console.error("Admin operation failed", {
        requestId: req.requestId,
        operation
    });

    return sendApiError(
        res,
        500,
        "admin_operation_failed",
        ERROR_MESSAGES.admin_operation_failed
    );
}

export default function createAdminRouter(env) {
    const router = Router();

    router.use((_req, res, next) => {
        res.set("Cache-Control", "no-store");
        next();
    });

    // Login is public, but must be same-origin and rate-limited.
    router.post(
        "/login",
        rateLimit(
            env,
            "ADMIN_LOGIN_LIMITER",
            req => req.get("cf-connecting-ip") || "local-development"
        ),
        async (req, res) => {
            if (!isSameOriginRequest(req)) {
                return sendApiError(
                    res,
                    403,
                    "cross_origin",
                    ERROR_MESSAGES.cross_origin
                );
            }

            const { username, password } = req.body ?? {};

            if (
                typeof username !== "string" ||
                typeof password !== "string" ||
                username.length > 64 ||
                password.length > 1024
            ) {
                return sendApiError(
                    res,
                    400,
                    "invalid_request",
                    "Enter a valid administrator username and password."
                );
            }

            try {
                const user = await verifyAdminCredentials(
                    env,
                    username,
                    password
                );

                if (!user) {
                    return sendApiError(
                        res,
                        401,
                        "unauthorized",
                        "Invalid administrator username or password."
                    );
                }

                const token = await createAdminSessionToken(
                    env,
                    user.username
                );

                setAdminSessionCookie(res, token, req);

                return res.json({
                    authenticated: true,
                    username: user.username,
                    expiresIn: SESSION_TTL_SECONDS
                });
            } catch {
                return sendInternalError(
                    res,
                    req,
                    "admin.login"
                );
            }
        }
    );

    // Logout only needs to clear the browser's cookie.
    router.post(
        "/logout",
        requireSameOrigin,
        (_req, res) => {
            clearAdminSessionCookie(res, _req);

            return res.json({
                authenticated: false
            });
        }
    );

    // Every operation below requires an administrator session.
    router.use(requireAdmin(env));

    // Enforce same-origin on all authenticated mutations in one place.
    router.use((req, res, next) => {
        if (["POST", "PATCH", "PUT", "DELETE"].includes(req.method)) {
            return requireSameOrigin(req, res, next);
        }

        return next();
    });

    router.get("/me", (req, res) => {
        return res.json({
            authenticated: true,
            username: req.adminUser
        });
    });

    // Create a CoreX client. The plaintext API key is returned once.
    router.post(
        "/clients",
        rateLimit(
            env,
            "ADMIN_CLIENT_CREATE_LIMITER",
            req => req.adminUser
        ),
        async (req, res) => {
            const { displayName } = req.body ?? {};

            if (
                typeof displayName !== "string" ||
                !displayName.trim() ||
                displayName.trim().length > 80 ||
                /[\u0000-\u001f\u007f]/.test(displayName)
            ) {
                return sendApiError(
                    res,
                    400,
                    "invalid_request",
                    "Enter a client name between 1 and 80 characters.",
                    "displayName"
                );
            }

            try {
                const client = await createCorexClient(env, {
                    displayName,
                    actor: req.adminUser
                });

                return res.status(201).json(client);
            } catch {
                return sendInternalError(
                    res,
                    req,
                    "client.create"
                );
            }
        }
    );

    router.get("/clients", async (req, res) => {
        try {
            const items = await getCorexClients(env, {
                query: req.query.q,
                limit: req.query.limit
            });

            return res.json({ items });
        } catch {
            return sendInternalError(
                res,
                req,
                "client.list"
            );
        }
    });

    router.get("/clients/:clientId", async (req, res) => {
        if (!validId(req.params.clientId)) {
            return sendApiError(
                res,
                400,
                "invalid_client_id",
                ERROR_MESSAGES.invalid_client_id
            );
        }

        try {
            const client = await getCorexClient(
                env,
                req.params.clientId
            );

            if (!client) {
                return sendApiError(
                    res,
                    404,
                    "client_not_found",
                    ERROR_MESSAGES.client_not_found
                );
            }

            return res.json(client);
        } catch {
            return sendInternalError(
                res,
                req,
                "client.inspect"
            );
        }
    });

    router.patch(
        "/clients/:clientId/scopes",
        async (req, res) => {
            const clientId = req.params.clientId;
            const scopes = req.body?.scopes;

            if (!validId(clientId)) {
                return sendApiError(
                    res,
                    400,
                    "invalid_client_id",
                    ERROR_MESSAGES.invalid_client_id
                );
            }

            if (
                !Array.isArray(scopes) ||
                !scopes.every(scope => scope === "auth")
            ) {
                return sendApiError(
                    res,
                    400,
                    "invalid_scopes",
                    ERROR_MESSAGES.invalid_scopes,
                    "scopes"
                );
            }

            try {
                const client = await updateCorexClientScopes(
                    env,
                    clientId,
                    scopes,
                    req.adminUser
                );

                if (!client) {
                    return sendApiError(
                        res,
                        404,
                        "client_not_found",
                        ERROR_MESSAGES.client_not_found
                    );
                }

                return res.json(client);
            } catch {
                return sendInternalError(
                    res,
                    req,
                    "client.scopes.update"
                );
            }
        }
    );

    router.post(
        "/clients/:clientId/revoke",
        async (req, res) => {
            const clientId = req.params.clientId;

            if (!validId(clientId)) {
                return sendApiError(
                    res,
                    400,
                    "invalid_client_id",
                    ERROR_MESSAGES.invalid_client_id
                );
            }

            try {
                const result = await revokeCorexClient(
                    env,
                    clientId,
                    req.adminUser
                );

                if (!result) {
                    return sendApiError(
                        res,
                        404,
                        "client_not_found",
                        ERROR_MESSAGES.client_not_found
                    );
                }

                return res.json(result);
            } catch {
                return sendInternalError(
                    res,
                    req,
                    "client.revoke"
                );
            }
        }
    );

    router.get("/audit", async (req, res) => {
        try {
            const items = await getAdminAudit(env, {
                limit: req.query.limit
            });

            return res.json({ items });
        } catch {
            return sendInternalError(
                res,
                req,
                "audit.list"
            );
        }
    });

    return router;
}