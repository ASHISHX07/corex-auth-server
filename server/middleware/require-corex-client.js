import { sha256Hex } from "../security/crypto.js";

export function requireCorexClient(env) {
    return async (req, res, next) => {
        const authorization = req.get("authorization") ?? "";
        const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(authorization);

        if (!match) {
            res.set("WWW-Authenticate", "Bearer");
            return res.status(401).json({
                error: "unauthorized"
            });
        }

        try {
            const apiKeyHash = await sha256Hex(match[1]);

            const client = await env.DB
                .prepare(`
                    SELECT corex_client_id, display_name
                    FROM corex_clients
                    WHERE api_key_hash = ?
                      AND status = 'active'
                    LIMIT 1
                `)
                .bind(apiKeyHash)
                .first();

            if (!client) {
                return res.status(401).json({
                    error: "unauthorized"
                });
            }

            const now = Math.floor(Date.now() / 1000);

            const update = await env.DB
                .prepare(`
                    UPDATE corex_clients
                    SET last_seen_at = ?
                    WHERE corex_client_id = ?
                      AND status = 'active'
                `)
                .bind(now, client.corex_client_id)
                .run();

            if (!update.success || update.meta.changes !== 1) {
                return res.status(401).json({
                    error: "unauthorized"
                });
            }

            req.corexClient = {
                id: client.corex_client_id,
                displayName: client.display_name
            };

            return next();
        } catch {
            // Never log API keys or authorization headers.
            return res.status(503).json({
                error: "authentication_unavailable"
            });
        }
    };
}