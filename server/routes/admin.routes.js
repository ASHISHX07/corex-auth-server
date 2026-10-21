import { Router } from "express";

import {
    requireAdmin,
    requireSameOriginForCookieAdmin,
    isSameOriginRequest
} from "../middleware/require-admin.js";

import { limitAdminLogin } from "../middleware/rate-limits.js";

import {
    createAdminSessionToken,
    setAdminSessionCookie,
    clearAdminSessionCookie,
    SESSION_TTL_SECONDS
} from "../security/admin-session.js";

import {
    getAdminOverview,
    getAdminRequests,
    getAdminClients,
    getAdminClientDetails,
    getAdminSessions,
    getAdminSessionDetails,
    invalidateAdminSession
} from "../services/admin-dashboard.service.js";

import { revokeCorexClient } from "../services/client-admin.service.js";

import { verifyAdminCredentials } from "../security/admin-credentials.js";

function validId(value) {
    return typeof value === "string" &&
        value.length > 0 &&
        value.length <= 100;
}

function sendInternalError(res, message) {
    console.error(message);

    return res.status(500).json({
        error: "admin_operation_failed"
    });
}

export default function createAdminRouter(env) {
    const router = Router();

    router.use((_req, res, next) => {
        res.set("Cache-Control", "no-store");
        next();
    });

    /*
    * Browser login.
    * The configured admin username and password are verified
    * before issuing a short-lived HttpOnly session cookie.
    */
    router.post(
        "/login",
        limitAdminLogin(env),
        async (req, res) => {
            res.set("Cache-Control", "no-store");

            if (!isSameOriginRequest(req)) {
                return res.status(403).json({
                    error: "Cross-origin request rejected."
                });
            }

            const { username, password } = req.body ?? {};

            if (
                typeof username !== "string" ||
                typeof password !== "string" ||
                username.length > 64 ||
                password.length > 1024
            ) {
                return res.status(401).json({
                    error: "Invalid username or password."
                });
            }

            let stage = "verify_credentials";

            try {
                const user = await verifyAdminCredentials(
                    env,
                    username,
                    password
                );

                if (!user) {
                    return res.status(401).json({
                        error: "Invalid username or password."
                    });
                }

                stage = "create_session_token";

                const token = await createAdminSessionToken(
                    env,
                    user.username
                );

                stage = "set_session_cookie";

                setAdminSessionCookie(res, token, req);

                return res.status(200).json({
                    authenticated: true,
                    username: user.username,
                    expiresIn: SESSION_TTL_SECONDS
                });
            } catch (error) {
                console.error("[admin-login] failed", {
                    stage,
                    errorName: error instanceof Error
                        ? error.name
                        : "UnknownError",
                    errorMessage: error instanceof Error
                        ? error.message.slice(0, 160)
                        : "Non-Error rejection"
                });

                return res.status(503).json({
                    error: "Admin authentication is unavailable."
                });
            }
        }
    );

    router.post("/logout", (req, res) => {
        res.set("Cache-Control", "no-store");

        if (!isSameOriginRequest(req)) {
            return res.status(403).json({
                error: "Cross-origin request rejected."
            });
        }

        clearAdminSessionCookie(res, req);

        return res.status(200).json({
            authenticated: false
        });
    });

    /*
     * Everything below this line requires a valid admin cookie
     * or a valid Bearer admin key.
     */
    router.use(requireAdmin(env));

    router.get("/me", (req, res) => {
        res.set("Cache-Control", "no-store");

        return res.json({
            authenticated: true,
            username: req.adminUser
        });
    });

    router.get("/overview", async (req, res) => {
        try {
            const overview = await getAdminOverview(
                env,
                req.query.period
            );

            return res.json(overview);
        } catch (error) {
            return sendInternalError(res, "Admin overview query failed");
        }
    });

    router.get("/requests", async (req, res) => {
        try {
            const result = await getAdminRequests(env, {
                limit: req.query.limit,
                cursor: req.query.cursor,
                period: req.query.period
            });
    
            return res.json(result);
        } catch (error) {
            if (error?.message === "invalid_request_cursor") {
                return res.status(400).json({
                    error: "invalid_request_cursor"
                });
            }
    
            return sendInternalError(
                res,
                "Admin request-log query failed"
            );
        }
    });

    router.get("/clients", async (req, res) => {
        try {
            const items = await getAdminClients(env, {
                query: req.query.q,
                limit: req.query.limit
            });

            return res.json({ items });
        } catch {
            return sendInternalError(res, "Admin client query failed");
        }
    });

    router.get("/clients/:clientId", async (req, res) => {
        if (!validId(req.params.clientId)) {
            return res.status(400).json({
                error: "invalid_client_id"
            });
        }

        try {
            const result = await getAdminClientDetails(
                env,
                req.params.clientId
            );

            if (!result) {
                return res.status(404).json({
                    error: "client_not_found"
                });
            }

            return res.json(result);
        } catch {
            return sendInternalError(res, "Admin client inspection failed");
        }
    });

    router.post(
        "/clients/:clientId/revoke",
        requireSameOriginForCookieAdmin,
        async (req, res) => {
            const clientId = req.params.clientId;

            if (!validId(clientId)) {
                return res.status(400).json({
                    error: "invalid_client_id"
                });
            }

            try {
                const result = await revokeCorexClient(env, clientId);

                if (!result) {
                    return res.status(404).json({
                        error: "client_not_found"
                    });
                }

                return res.json({
                    status: result.status,
                    expiredSessions: result.expiredSessions
                });
            } catch {
                return sendInternalError(res, "Client revocation failed");
            }
        }
    );

    router.get("/sessions", async (req, res) => {
        try {
            const status = typeof req.query.status === "string"
                ? req.query.status
                : "";

            const broker = typeof req.query.broker === "string"
                ? req.query.broker.trim().toLowerCase()
                : "";

            const items = await getAdminSessions(env, {
                limit: req.query.limit,
                status,
                broker
            });

            return res.json({ items });
        } catch {
            return sendInternalError(res, "Admin session query failed");
        }
    });

    router.get("/sessions/:sessionId", async (req, res) => {
        if (!validId(req.params.sessionId)) {
            return res.status(400).json({
                error: "invalid_session_id"
            });
        }

        try {
            const session = await getAdminSessionDetails(
                env,
                req.params.sessionId
            );

            if (!session) {
                return res.status(404).json({
                    error: "session_not_found"
                });
            }

            return res.json(session);
        } catch {
            return sendInternalError(res, "Admin session inspection failed");
        }
    });

    router.post(
        "/sessions/:sessionId/invalidate",
        requireSameOriginForCookieAdmin,
        async (req, res) => {
            const sessionId = req.params.sessionId;

            if (!validId(sessionId)) {
                return res.status(400).json({
                    error: "invalid_session_id"
                });
            }

            try {
                const result = await invalidateAdminSession(
                    env,
                    sessionId
                );

                if (result.outcome === "not_found") {
                    return res.status(404).json({
                        error: "session_not_found"
                    });
                }

                if (result.outcome === "not_active") {
                    return res.status(409).json({
                        error: "session_not_invalidatable",
                        status: result.session.status
                    });
                }

                return res.json({
                    status: result.session.status,
                    failure_code: result.session.failure_code
                });
            } catch {
                return sendInternalError(res, "Session invalidation failed");
            }
        }
    );

    return router;
}