import { sendApiError } from "./errors.js";

function clientIpKey(req) {
    const ip = req.get("cf-connecting-ip");

    return typeof ip === "string" && ip.length <= 64
        ? `ip:${ip}`
        : "local-development";
}

function createLimiter(bindingName, keyOf, { json }) {
    return env => async (req, res, next) => {
        const unavailable = () => {
            if (json) {
                return sendApiError(
                    res,
                    503,
                    "service_unavailable",
                    "Rate limiting is temporarily unavailable."
                );
            }

            return res.status(503).send(
                "Service temporarily unavailable."
            );
        };

        try {
            const limiter = env[bindingName];

            if (!limiter) {
                return unavailable();
            }

            const { success } = await limiter.limit({
                key: keyOf(req)
            });

            if (success) {
                return next();
            }

            res.set("Retry-After", "60");

            if (json) {
                return sendApiError(
                    res,
                    429,
                    "rate_limit_exceeded",
                    "Too many requests. Please retry later."
                );
            }

            return res.status(429).send(
                "Too many requests. Please retry later."
            );
        } catch {
            return unavailable();
        }
    };
}

const byClient = req => req.corexClient.id;

export const limitSessionCreation = createLimiter(
    "AUTH_SESSION_LIMITER",
    byClient,
    { json: true }
);

export const limitSessionPolling = createLimiter(
    "AUTH_POLL_LIMITER",
    byClient,
    { json: true }
);

export const limitCallbacks = createLimiter(
    "CALLBACK_LIMITER",
    clientIpKey,
    { json: false }
);

export const limitAdminLogin = createLimiter(
    "ADMIN_LOGIN_LIMITER",
    clientIpKey,
    { json: true }
);
