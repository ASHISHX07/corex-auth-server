function clientIpKey(req) {
    const ip = req.get("cf-connecting-ip");
    // Cloudflare sets this header at the edge; local dev shares one bucket.
    return typeof ip === "string" && ip.length <= 64 ? `ip:${ip}` : "local-development";
}

function createLimiter(bindingName, keyOf, { json }) {
    return env => async (req, res, next) => {
        const unavailable = () => json
            ? res.status(503).json({ error: "rate_limiter_unavailable" })
            : res.status(503).send("Service temporarily unavailable.");

        try {
            const limiter = env[bindingName];
            if (!limiter) return unavailable();

            const { success } = await limiter.limit({ key: keyOf(req) });
            if (success) return next();

            res.set("Retry-After", "60");
            return json
                ? res.status(429).json({ error: "rate_limit_exceeded", retryAfterSeconds: 60 })
                : res.status(429).send("Too many requests. Please retry later.");
        } catch {
            return unavailable();
        }
    };
}

const byClient = req => req.corexClient.id;

export const limitSessionCreation = createLimiter("AUTH_SESSION_LIMITER", byClient, { json: true });
export const limitSessionPolling = createLimiter("AUTH_POLL_LIMITER", byClient, { json: true });
export const limitCallbacks = createLimiter("CALLBACK_LIMITER", clientIpKey, { json: false });
export const limitAdminLogin = createLimiter("ADMIN_LOGIN_LIMITER", clientIpKey, { json: true });
