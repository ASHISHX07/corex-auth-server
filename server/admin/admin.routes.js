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

export default function createAdminRouter(env) {
    const router = Router();

    router.use((_req, res, next) => {
        res.set("Cache-Control", "no-store");
        next();
    });

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
                    "Cross-origin request rejected."
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

                return res.status(200).json({
                    authenticated: true,
                    username: user.username,
                    expiresIn: SESSION_TTL_SECONDS
                });
            } catch {
                console.error("Administrator login failed", {
                    requestId: req.requestId
                });

                return sendApiError(
                    res,
                    503,
                    "authentication_unavailable",
                    "Administrator authentication is temporarily unavailable."
                );
            }
        }
    );

    router.post(
        "/logout",
        requireSameOrigin,
        (req, res) => {
            clearAdminSessionCookie(res, req);

            return res.json({
                authenticated: false
            });
        }
    );

    // All routes below require a valid administrator session.
    router.use(requireAdmin(env));

    router.get("/me", (req, res) => {
        return res.json({
            authenticated: true,
            username: req.adminUser
        });
    });

    return router;
}