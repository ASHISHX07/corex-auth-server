const CALLBACK_PATH =
    /^\/auth\/([a-z0-9_-]{2,32})\/callback$/;

const RESULT_PATH =
    /^\/api\/v3\/auth\/sessions\/[^/]+\/result$/;

function normalizePath(path) {
    if (RESULT_PATH.test(path)) {
        return "/api/v3/auth/sessions/:sessionId/result";
    }

    if (CALLBACK_PATH.test(path)) {
        return "/auth/:broker/callback";
    }

    return path;
}

function getBroker(req, callbackMatch) {
    const bodyBroker = req.body?.broker;

    if (
        typeof bodyBroker === "string" &&
        /^[a-z0-9_-]{2,32}$/.test(bodyBroker)
    ) {
        return bodyBroker;
    }

    return callbackMatch?.[1] ?? null;
}

export function requestLogger(env, waitUntil) {
    return (req, res, next) => {
        const path = req.path;
        const callbackMatch = CALLBACK_PATH.exec(path);

        const isAdminRequest =
            path.startsWith("/api/v3/admin/");

        const shouldLog =
            !isAdminRequest &&
            (
                path.startsWith("/api/") ||
                callbackMatch !== null
            );

        if (
            !shouldLog ||
            !env?.DB ||
            typeof waitUntil !== "function"
        ) {
            return next();
        }

        const startedAt = Date.now();

        res.once("finish", () => {
            // Pending polls are intentionally excluded:
            // they can otherwise generate thousands of D1 writes.
            if (
                res.statusCode === 202 &&
                RESULT_PATH.test(path)
            ) {
                return;
            }

            const now = Math.floor(Date.now() / 1000);

            const broker = getBroker(req, callbackMatch);

            const durationMs = Math.max(
                0,
                Date.now() - startedAt
            );

            const task = env.DB.prepare(`
                INSERT INTO request_logs (
                    request_id,
                    method,
                    path,
                    status_code,
                    duration_ms,
                    corex_client_id,
                    broker,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(
                req.requestId,
                req.method,
                normalizePath(path),
                res.statusCode,
                durationMs,
                req.corexClient?.id ?? null,
                broker,
                now
            ).run().catch(() => {
                console.error("Request logging failed", {
                    requestId: req.requestId
                });
            });

            // Persist the log asynchronously without delaying the response.
            try {
                waitUntil(task);
            } catch {
                task.catch(() => {});
            }
        });

        next();
    };
}