import { sha256Hex } from "../security/hashing.js";
import { sendApiError } from "./errors.js";

const CLIENT_KEY_PATTERN =
    /^Bearer (cx_[A-Za-z0-9_-]{43})$/i

const SCOPE_PATTERN =
    /^[a-z][a-z0-9:_-]{0,63}$/;

const LAST_SEEN_INTERVAL_SECONDS = 300;

function parseScopes(value) {
    let scopes;

    try {
        scopes = JSON.parse(value);
    } catch {
        throw new Error("Invalid stored client scopes.");
    }

    if (
        !Array.isArray(scopes) ||
        !scopes.every(
            scope =>
                typeof scope === "string" &&
                SCOPE_PATTERN.test(scope)
        )
    ) {
        throw new Error("Invalid stored client scopes.");
    }

    return [...new Set(scopes)];
}

function unauthorized(res) {
    res.set("WWW-Authenticate", "Bearer");

    return sendApiError(
        res,
        401,
        "unauthorized",
        "A valid CoreX client key is required."
    );
}

export function requireClientAuth(env, requiredScope) {
    if (
        typeof requiredScope !== "string" ||
        !SCOPE_PATTERN.test(requiredScope)
    ) {
        throw new TypeError("Invalid required client scope.");
    }

    return async (req, res, next) => {
        const authorization = req.get("authorization") ?? "";
        const match = CLIENT_KEY_PATTERN.exec(authorization);

        if (!match) {
            return unauthorized(res);
        }

        try {
            if (!env?.DB) {
                throw new Error("Database binding is missing.");
            }

            const keyHash = await sha256Hex(match[1]);

            const client = await env.DB.prepare(`
                SELECT
                    corex_client_id,
                    display_name,
                    scopes,
                    last_seen_at
                FROM corex_clients
                WHERE api_key_hash = ?
                  AND status = 'active'
                LIMIT 1
            `).bind(keyHash).first();

            if (!client) {
                return unauthorized(res);
            }

            const scopes = parseScopes(client.scopes);

            if (!scopes.includes(requiredScope)) {
                return sendApiError(
                    res,
                    403,
                    "forbidden_scope",
                    "The client is missing the required scope."
                );
            }

            const now = Math.floor(Date.now() / 1000);
            const lastSeen = Number(client.last_seen_at);

            if (
                !Number.isFinite(lastSeen) ||
                now - lastSeen >= LAST_SEEN_INTERVAL_SECONDS
            ) {
                const update = await env.DB.prepare(`
                    UPDATE corex_clients
                    SET last_seen_at = ?
                    WHERE corex_client_id = ?
                      AND status = 'active'
                `).bind(now, client.corex_client_id).run();

                if (update.meta?.changes !== 1) {
                    return unauthorized(res);
                }
            }

            req.corexClient = {
                id: client.corex_client_id,
                displayName: client.display_name,
                scopes
            };

            return next();
        } catch {
            return sendApiError(
                res,
                503,
                "authentication_unavailable",
                "Client authentication is temporarily unavailable."
            );
        }
    };
}