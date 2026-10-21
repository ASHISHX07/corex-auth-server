export function limitSessionCreation(env) {
    return async (req, res, next) => {
        try {
            if (!env.AUTH_SESSION_LIMITER) {
                return res.status(503).json({
                    error: "rate_limiter_unavailable"
                });
            }

            const { success } = await env.AUTH_SESSION_LIMITER.limit({
                key: req.corexClient.id
            });

            if (!success) {
                res.set("Retry-After", "60");

                return res.status(429).json({
                    error: "rate_limit_exceeded",
                    retryAfterSeconds: 60
                });
            }

            return next();
        } catch {
            return res.status(503).json({
                error: "rate_limiter_unavailable"
            });
        }
    };
}

export function limitUpstoxCallbacks(env) {
    return async (req, res, next) => {
        try {
            if (!env.UPSTOX_CALLBACK_LIMITER) {
                return res.status(503).send(
                    "Callback service temporarily unavailable."
                );
            }

            // Cloudflare sets this header for requests reaching its edge.
            // For local development, use a shared local-test bucket.
            const ip = req.get("cf-connecting-ip");
            const key =
                typeof ip === "string" && ip.length <= 64
                    ? `ip:${ip}`
                    : "local-development";

            const { success } = await env.UPSTOX_CALLBACK_LIMITER.limit({
                key
            });

            if (!success) {
                res.set("Retry-After", "60");

                return res.status(429).send(
                    "Too many callback requests. Please retry later."
                );
            }

            return next();
        } catch {
            return res.status(503).send(
                "Callback service temporarily unavailable."
            );
        }
    };
}

export function limitAdminLogin(env) {
    return async (req, res, next) => {
        try {
            if (!env.ADMIN_LOGIN_LIMITER) {
                return res.status(503).json({
                    error: "admin_login_limiter_unavailable"
                });
            }

            const ip = req.get("cf-connecting-ip");

            const key =
                typeof ip === "string" && ip.length <= 64
                    ? `ip:${ip}`
                    : "local-development";

            const { success } = await env.ADMIN_LOGIN_LIMITER.limit({
                key
            });

            if (!success) {
                res.set("Retry-After", "60");

                return res.status(429).json({
                    error: "rate_limit_exceeded",
                    retryAfterSeconds: 60
                });
            }

            return next();
        } catch {
            return res.status(503).json({
                error: "rate_limiter_unavailable"
            });
        }
    };
}