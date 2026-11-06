import { sendApiError } from "./errors.js";

function unavailable(req, res) {
    if (req.originalUrl?.startsWith("/api/")) {
        return sendApiError(
            res,
            503,
            "authentication_unavailable",
            "Authentication is temporarily unavailable."
        );
    }

    return res
        .status(503)
        .type("text/plain")
        .send("Authentication is temporarily unavailable.");
}

export function rateLimit(env, bindingName, getKey) {
    return async (req, res, next) => {
        const limiter = env?.[bindingName];

        // Fail closed when a configured production binding is missing.
        if (!limiter || typeof limiter.limit !== "function") {
            return unavailable(req, res);
        }

        try {
            const key = getKey(req);

            if (typeof key !== "string" || !key) {
                throw new Error("Invalid rate-limit key.");
            }

            const result = await limiter.limit({ key });

            if (result.success) {
                return next();
            }
        } catch {
            console.error("Rate limit check failed", {
                requestId: req.requestId,
                binding: bindingName
            });

            return unavailable(req, res);
        }

        res.set("Retry-After", "60");

        if (req.originalUrl?.startsWith("/api/")) {
            return sendApiError(
                res,
                429,
                "rate_limit_exceeded",
                "Too many requests. Try again after the specified interval."
            );
        }

        return res
            .status(429)
            .type("text/plain")
            .send("Too many callback requests. Please try again later.");
    };
}