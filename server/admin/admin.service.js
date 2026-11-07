import { randomBase64Url } from "../security/encoding.js";
import { sha256Hex } from "../security/hashing.js";

const DEFAULT_SCOPES = ["auth"];
const ALLOWED_SCOPES = new Set(["auth"]);

function nowSeconds() {
    return Math.floor(Date.now() / 1000);
}

function toIso(value) {
    return value == null
        ? null
        : new Date(Number(value) * 1000).toISOString();
}

function normalizeLimit(value, fallback = 50) {
    const parsed = Number(value);

    if (!Number.isInteger(parsed) || parsed < 1) {
        return fallback;
    }

    return Math.min(parsed, 100);
}

function parseScopes(value) {
    let scopes;

    try {
        scopes = JSON.parse(value);
    } catch {
        throw new Error("Invalid stored client scopes.");
    }

    if (
        !Array.isArray(scopes) ||
        !scopes.every(scope =>
            typeof scope === "string" &&
            ALLOWED_SCOPES.has(scope)
        )
    ) {
        throw new Error("Invalid stored client scopes.");
    }

    return [...new Set(scopes)];
}

function mapClient(row) {
    return {
        clientId: row.corex_client_id,
        displayName: row.display_name,
        keyHint: row.key_hint,
        scopes: parseScopes(row.scopes),
        status: row.status,
        createdAt: toIso(row.created_at),
        createdBy: row.created_by,
        lastSeenAt: toIso(row.last_seen_at),
        totalSessions: Number(row.total_sessions ?? 0),
        openSessions: Number(row.open_sessions ?? 0)
    };
}

function auditInsert(env, {
    actor,
    action,
    targetType,
    targetId
}) {
    return env.DB.prepare(`
        INSERT INTO admin_audit (
            id,
            at,
            actor,
            action,
            target_type,
            target_id
        )
        VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
        crypto.randomUUID(),
        nowSeconds(),
        actor,
        action,
        targetType,
        targetId
    );
}

export async function createCorexClient(
    env,
    { displayName, actor }
) {
    if (
        typeof displayName !== "string" ||
        !displayName.trim() ||
        displayName.trim().length > 80 ||
        /[\u0000-\u001f\u007f]/.test(displayName)
    ) {
        throw new TypeError("Invalid client display name.");
    }

    if (typeof actor !== "string" || !actor) {
        throw new TypeError("Invalid administrator identity.");
    }

    const name = displayName.trim();

    // 256 bits of randomness, encoded as 43 Base64URL characters.
    const apiKey = `cx_${randomBase64Url(32)}`;
    const keyHash = await sha256Hex(apiKey);
    const clientId = crypto.randomUUID();
    const keyHint = apiKey.slice(-4);
    const now = nowSeconds();

    // Client record and audit event must succeed together.
    const results = await env.DB.batch([
        env.DB.prepare(`
            INSERT INTO corex_clients (
                corex_client_id,
                api_key_hash,
                key_hint,
                display_name,
                scopes,
                status,
                created_at,
                created_by
            )
            VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
        `).bind(
            clientId,
            keyHash,
            keyHint,
            name,
            JSON.stringify(DEFAULT_SCOPES),
            now,
            actor
        ),

        auditInsert(env, {
            actor,
            action: "client.create",
            targetType: "client",
            targetId: clientId
        })
    ]);

    if (
        results[0]?.meta?.changes !== 1 ||
        results[1]?.meta?.changes !== 1
    ) {
        throw new Error("Client creation was not committed.");
    }

    // This is the only response containing the plaintext key.
    return {
        clientId,
        displayName: name,
        apiKey,
        keyHint,
        scopes: DEFAULT_SCOPES,
        status: "active",
        createdAt: toIso(now)
    };
}

export async function getCorexClients(
    env,
    { query = "", limit } = {}
) {
    const search = typeof query === "string"
        ? query.trim().slice(0, 80)
        : "";

    const rows = await env.DB.prepare(`
        SELECT
            c.corex_client_id,
            c.display_name,
            c.key_hint,
            c.scopes,
            c.status,
            c.created_at,
            c.created_by,
            c.last_seen_at,

            (
                SELECT COUNT(*)
                FROM auth_sessions s
                WHERE s.corex_client_id = c.corex_client_id
                  AND s.api_version = 3
            ) AS total_sessions,

            (
                SELECT COUNT(*)
                FROM auth_sessions s
                WHERE s.corex_client_id = c.corex_client_id
                  AND s.api_version = 3
                  AND s.status IN ('pending', 'processing', 'ready')
            ) AS open_sessions

        FROM corex_clients c
        WHERE (? = '' OR instr(lower(c.display_name), lower(?)) > 0)
        ORDER BY c.created_at DESC, c.corex_client_id DESC
        LIMIT ?
    `).bind(
        search,
        search,
        normalizeLimit(limit)
    ).all();

    return rows.results.map(mapClient);
}

export async function getCorexClient(env, clientId) {
    const row = await env.DB.prepare(`
        SELECT
            c.corex_client_id,
            c.display_name,
            c.key_hint,
            c.scopes,
            c.status,
            c.created_at,
            c.created_by,
            c.last_seen_at,

            (
                SELECT COUNT(*)
                FROM auth_sessions s
                WHERE s.corex_client_id = c.corex_client_id
                  AND s.api_version = 3
            ) AS total_sessions,

            (
                SELECT COUNT(*)
                FROM auth_sessions s
                WHERE s.corex_client_id = c.corex_client_id
                  AND s.api_version = 3
                  AND s.status IN ('pending', 'processing', 'ready')
            ) AS open_sessions

        FROM corex_clients c
        WHERE c.corex_client_id = ?
    `).bind(clientId).first();

    return row ? mapClient(row) : null;
}

export async function updateCorexClientScopes(
    env,
    clientId,
    scopes,
    actor
) {
    if (
        !Array.isArray(scopes) ||
        !scopes.every(scope =>
            typeof scope === "string" &&
            ALLOWED_SCOPES.has(scope)
        )
    ) {
        throw new TypeError("Invalid client scopes.");
    }

    if (typeof actor !== "string" || !actor) {
        throw new TypeError("Invalid administrator identity.");
    }

    const normalizedScopes = [...new Set(scopes)];
    const scopesJson = JSON.stringify(normalizedScopes);

    const results = await env.DB.batch([
        env.DB.prepare(`
            UPDATE corex_clients
            SET scopes = ?
            WHERE corex_client_id = ?
              AND scopes != ?
        `).bind(scopesJson, clientId, scopesJson),

        // Only write an audit row when the scopes actually changed.
        env.DB.prepare(`
            INSERT INTO admin_audit (
                id, at, actor, action, target_type, target_id
            )
            SELECT ?, ?, ?, 'client.scopes.update', 'client', ?
            WHERE changes() = 1
        `).bind(
            crypto.randomUUID(),
            nowSeconds(),
            actor,
            clientId
        )
    ]);

    const client = await getCorexClient(env, clientId);

    if (!client) {
        return null;
    }

    return {
        ...client,
        changed: results[0]?.meta?.changes === 1
    };
}

export async function revokeCorexClient(
    env,
    clientId,
    actor
) {
    if (typeof actor !== "string" || !actor) {
        throw new TypeError("Invalid administrator identity.");
    }

    const results = await env.DB.batch([
        env.DB.prepare(`
            UPDATE corex_clients
            SET status = 'revoked'
            WHERE corex_client_id = ?
              AND status = 'active'
        `).bind(clientId),

        // Record the revocation only when the client changed state.
        env.DB.prepare(`
            INSERT INTO admin_audit (
                id, at, actor, action, target_type, target_id
            )
            SELECT ?, ?, ?, 'client.revoke', 'client', ?
            WHERE changes() = 1
        `).bind(
            crypto.randomUUID(),
            nowSeconds(),
            actor,
            clientId
        ),

        // Revoke also cancels unfinished V3 sessions and removes
        // any temporary codes or encrypted results.
        env.DB.prepare(`
            UPDATE auth_sessions
            SET
                status = 'cancelled',
                authorization_code = NULL,
                result_ciphertext = NULL,
                failure_code = 'client_revoked'
            WHERE corex_client_id = ?
              AND api_version = 3
              AND status IN ('pending', 'processing', 'ready')
        `).bind(clientId)
    ]);

    const client = await getCorexClient(env, clientId);

    if (!client) {
        return null;
    }

    return {
        clientId,
        status: client.status,
        changed: results[0]?.meta?.changes === 1,
        cancelledSessions: results[2]?.meta?.changes ?? 0
    };
}

export async function getAdminAudit(env, { limit } = {}) {
    const rows = await env.DB.prepare(`
        SELECT
            id,
            at,
            actor,
            action,
            target_type,
            target_id
        FROM admin_audit
        ORDER BY at DESC, id DESC
        LIMIT ?
    `).bind(normalizeLimit(limit)).all();

    return rows.results.map(row => ({
        id: row.id,
        at: toIso(row.at),
        actor: row.actor,
        action: row.action,
        targetType: row.target_type,
        targetId: row.target_id
    }));
}