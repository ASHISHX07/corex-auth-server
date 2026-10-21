import {
    readAdminSessionCookie,
    verifyAdminSessionToken
} from "../security/admin-session.js";

function constantTimeEqualStrings(a, b) {
    if (
        typeof a !== "string" ||
        typeof b !== "string" ||
        a.length !== b.length
    ) {
        return false;
    }

    let difference = 0;

    for (let i = 0; i < a.length; i++) {
        difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return difference === 0;
}

export function isSameOriginRequest(req) {
    const origin = req.get("origin");
    const host = req.get("host");

    if (!origin || !host) {
        return false;
    }

    try {
        const originUrl = new URL(origin);

        return (
            originUrl.host.toLowerCase() === host.toLowerCase() &&
            ["http:", "https:"].includes(originUrl.protocol)
        );
    } catch {
        return false;
    }
}

export function requireSameOriginForCookieAdmin(req, res, next) {
    // Safe read-only requests don't need this additional check.
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
        return next();
    }

    // Existing bearer-key API access remains usable by API clients.
    if (req.adminAuth === "bearer") {
        return next();
    }

    if (!isSameOriginRequest(req)) {
        return res.status(403).json({
            error: "Cross-origin request rejected."
        });
    }

    return next();
}

export function requireAdmin(env) {
    return async function adminAuthentication(req, res, next) {
        try {
            const authorization =
                req.get("authorization") || "";

            if (authorization.startsWith("Bearer ")) {
                const suppliedKey = authorization.slice(7);
                const expectedKey = env.COREX_ADMIN_API_KEY;

                if (
                    expectedKey &&
                    constantTimeEqualStrings(suppliedKey, expectedKey)
                ) {
                    req.adminAuth = "bearer";
                    req.adminUser = "admin-api";

                    return next();
                }

                return res.status(401).json({
                    error: "Unauthorized."
                });
            }

            const sessionToken = readAdminSessionCookie(req);

            if (sessionToken) {
                const claims = await verifyAdminSessionToken(
                    env,
                    sessionToken
                );

                if (claims) {
                    req.adminAuth = "cookie";
                    req.adminUser = claims.sub;

                    return next();
                }
            }

            return res.status(401).json({
                error: "Unauthorized."
            });
        } catch {
            return res.status(500).json({
                error: "Authentication could not be completed."
            });
        }
    };
}