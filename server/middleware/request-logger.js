import { waitUntil } from "cloudflare:workers";

const ALLOWED_BROKERS = new Set(["upstox", "fyers", "zerodha"]);

function normalizePath(path) {
    const patterns = [
        [
            /^\/api\/v1\/auth\/sessions\/[^/]+\/result$/,
            "/api/v1/auth/sessions/:sessionId/result"
        ],
        [
            /^\/api\/v1\/admin\/clients\/[^/]+\/revoke$/,
            "/api/v1/admin/clients/:clientId/revoke"
        ],
        [
            /^\/api\/v1\/admin\/clients\/[^/]+$/,
            "/api/v1/admin/clients/:clientId"
        ],
        [
            /^\/api\/v1\/admin\/sessions\/[^/]+\/invalidate$/,
            "/api/v1/admin/sessions/:sessionId/invalidate"
        ],
        [
            /^\/api\/v1\/admin\/sessions\/[^/]+$/,
            "/api/v1/admin/sessions/:sessionId"
        ]
    ];

    for (const [pattern, replacement] of patterns) {
        if (pattern.test(path)) {
            return replacement;
        }
    }

    return path;
}

export function requestLogger(env) {
    return (req, res, next) => {
        const path = req.path;

        const isAdminConsoleApi =
            path.startsWith("/api/v1/admin/");

        const shouldLog =
            (path.startsWith("/api/") && !isAdminConsoleApi) ||
            path === "/auth/upstox/callback";

        if (!shouldLog) {
            return next();
        }

        const startedAt = Date.now();

        res.once("finish", () => {
            if (!env.DB) {
                return;
            }

            const now = Math.floor(Date.now() / 1000);
            const brokerFromBody =
                typeof req.body?.broker === "string"
                    ? req.body.broker.trim().toLowerCase()
                    : "";

            const broker = ALLOWED_BROKERS.has(brokerFromBody)
                ? brokerFromBody
                : path === "/auth/upstox/callback"
                    ? "upstox"
                    : null;

            const normalizedPath = normalizePath(path);
            const clientId = req.corexClient?.id ?? null;
            const durationMs = Math.max(0, Date.now() - startedAt);

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
                crypto.randomUUID(),
                req.method,
                normalizedPath,
                res.statusCode,
                durationMs,
                clientId,
                broker,
                now
            ).run().catch(() => {
                // Logging must not break the user's request.
                console.error("Request logging failed");
            });

            try {
                waitUntil(task);
            } catch {
                // Defensive fallback for runtimes without an active context.
                // The database promise has already been started.
                task.catch(() => {});
            }
        });

        return next();
    };
}