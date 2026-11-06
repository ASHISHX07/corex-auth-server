import {
    readAdminSessionCookie,
    verifyAdminSessionToken
} from "../security/admin-session.js";

import { sendApiError } from "../gateway/errors.js";

export function isSameOriginRequest(req) {
    const origin = req.get("origin");
    const host = req.get("host");

    if (!origin || !host) {
        return false;
    }

    try {
        const url = new URL(origin);

        return (
            url.host.toLowerCase() === host.toLowerCase() &&
            ["http:", "https:"].includes(url.protocol)
        );
    } catch {
        return false;
    }
}

export function requireSameOrigin(req, res, next) {
    if (!isSameOriginRequest(req)) {
        return sendApiError(
            res,
            403,
            "cross_origin",
            "Cross-origin request rejected."
        );
    }

    return next();
}

export function requireAdmin(env) {
    return async (req, res, next) => {
        const token = readAdminSessionCookie(req);

        if (!token) {
            return sendApiError(
                res,
                401,
                "unauthorized",
                "Administrator authentication is required."
            );
        }

        try {
            const claims = await verifyAdminSessionToken(env, token);

            if (!claims) {
                return sendApiError(
                    res,
                    401,
                    "unauthorized",
                    "Administrator authentication is required."
                );
            }

            req.adminUser = claims.sub;

            return next();
        } catch {
            console.error("Administrator session validation failed", {
                requestId: req.requestId
            });

            return sendApiError(
                res,
                503,
                "authentication_unavailable",
                "Administrator authentication is temporarily unavailable."
            );
        }
    };
}