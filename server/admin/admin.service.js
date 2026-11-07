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

const DASHBOARD_PERIODS = Object.freeze({
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400
});

const DASHBOARD_SESSION_STATUSES = new Set([
    "pending",
    "code_received",
    "processing",
    "ready",
    "retrieved",
    "failed",
    "expired",
    "cancelled"
]);

function getDashboardPeriod(value = "24h") {
    const period = DASHBOARD_PERIODS[value];

    if (!period) {
        throw new TypeError("Invalid dashboard period.");
    }

    const to = nowSeconds();

    return {
        period: value,
        from: to - period,
        to
    };
}

function mapSession(row) {
    return {
        sessionId: row.session_id,
        clientId: row.corex_client_id,
        clientName: row.client_display_name,
        broker: row.broker,
        providerAppId: row.provider_app_id,
        apiVersion: Number(row.api_version),
        status: row.status,
        createdAt: toIso(row.created_at),
        expiresAt: toIso(row.expires_at),
        callbackReceivedAt: toIso(row.callback_received_at),
        retrievedAt: toIso(row.retrieved_at),
        failureCode: row.failure_code,
        hasAuthorizationCode: Boolean(row.has_authorization_code),
        hasResult: Boolean(row.has_result)
    };
}

export async function getAdminOverview(env, { period: periodInput } = {}) {
    const range = getDashboardPeriod(periodInput);

    const utcToday = Math.floor(range.to / 86400) * 86400;

    const [
        requestStats,
        clientStats,
        sessionRows,
        failureRows,
        brokerRows,
        chartRows
    ] = await Promise.all([
        env.DB.prepare(`
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(status_code < 400), 0) AS successful,
                COALESCE(SUM(status_code >= 400), 0) AS failed,
                COALESCE(AVG(duration_ms), 0) AS average_latency_ms
            FROM request_logs
            WHERE created_at >= ?
              AND created_at <= ?
        `).bind(range.from, range.to).first(),

        env.DB.prepare(`
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(status = 'active'), 0) AS active,
                COALESCE(SUM(status = 'revoked'), 0) AS revoked
            FROM corex_clients
        `).first(),

        env.DB.prepare(`
            SELECT status, COUNT(*) AS count
            FROM auth_sessions
            WHERE created_at >= ?
              AND created_at <= ?
            GROUP BY status
        `).bind(range.from, range.to).all(),

        env.DB.prepare(`
            SELECT
                COALESCE(failure_code, 'unknown') AS code,
                COUNT(*) AS count
            FROM auth_sessions
            WHERE created_at >= ?
              AND created_at <= ?
              AND status = 'failed'
            GROUP BY failure_code
            ORDER BY count DESC, code
        `).bind(range.from, range.to).all(),

        env.DB.prepare(`
            SELECT
                broker,
                SUM(status IN ('ready', 'retrieved')) AS successful,
                SUM(status = 'failed') AS failed
            FROM auth_sessions
            WHERE created_at >= ?
              AND created_at <= ?
              AND status IN ('ready', 'retrieved', 'failed')
            GROUP BY broker
            ORDER BY broker
        `).bind(range.from, range.to).all(),

        env.DB.prepare(`
            SELECT
                strftime(
                    '${range.period === "24h"
                        ? "%Y-%m-%dT%H:00:00Z"
                        : "%Y-%m-%dT00:00:00Z"}',
                    created_at,
                    'unixepoch'
                ) AS bucket,
                COUNT(*) AS requests,
                COALESCE(SUM(status_code >= 400), 0) AS failed
            FROM request_logs
            WHERE created_at >= ?
              AND created_at <= ?
            GROUP BY bucket
            ORDER BY bucket
        `).bind(range.from, range.to).all()
    ]);

    const sessions = {
        total: 0,
        pending: 0,
        codeReceived: 0,
        processing: 0,
        ready: 0,
        retrieved: 0,
        failed: 0,
        expired: 0,
        cancelled: 0,
        active: 0
    };

    const statusNames = {
        pending: "pending",
        code_received: "codeReceived",
        processing: "processing",
        ready: "ready",
        retrieved: "retrieved",
        failed: "failed",
        expired: "expired",
        cancelled: "cancelled"
    };

    for (const row of sessionRows.results) {
        const name = statusNames[row.status];

        if (name) {
            sessions[name] = Number(row.count);
            sessions.total += Number(row.count);
        }
    }

    sessions.active =
        sessions.pending +
        sessions.codeReceived +
        sessions.processing +
        sessions.ready;

    const requestTotal = Number(requestStats.total);
    const requestSuccessful = Number(requestStats.successful);
    const requestFailed = Number(requestStats.failed);

    return {
        period: range.period,
        generatedAt: toIso(range.to),

        requests: {
            total: requestTotal,
            successful: requestSuccessful,
            failed: requestFailed,
            successRate: requestTotal
                ? Number((requestSuccessful / requestTotal * 100).toFixed(1))
                : 0,
            averageLatencyMs: Math.round(
                Number(requestStats.average_latency_ms)
            )
        },

        usage: {
            requestsToday: Number(
                (await env.DB.prepare(`
                    SELECT COUNT(*) AS total
                    FROM request_logs
                    WHERE created_at >= ?
                `).bind(utcToday).first()).total
            )
        },

        clients: {
            total: Number(clientStats.total),
            active: Number(clientStats.active),
            revoked: Number(clientStats.revoked)
        },

        sessions,

        failureReasons: failureRows.results.map(row => ({
            code: row.code,
            count: Number(row.count)
        })),

        brokerStats: brokerRows.results.map(row => {
            const successful = Number(row.successful ?? 0);
            const failed = Number(row.failed ?? 0);
            const total = successful + failed;

            return {
                broker: row.broker,
                total,
                successful,
                failed,
                successRate: total
                    ? Number((successful / total * 100).toFixed(1))
                    : 0
            };
        }),

        chart: chartRows.results.map(row => ({
            bucket: row.bucket,
            requests: Number(row.requests),
            failed: Number(row.failed)
        }))
    };
}

export async function getAdminRequests(
    env,
    { period: periodInput, limit: limitInput, offset: offsetInput } = {}
) {
    const range = getDashboardPeriod(periodInput);

    const limit = normalizeLimit(limitInput, 25);
    const offset = Math.max(
        0,
        Math.min(Number.isInteger(Number(offsetInput))
            ? Number(offsetInput)
            : 0, 10000)
    );

    const rows = await env.DB.prepare(`
        SELECT
            r.request_id,
            r.method,
            r.path,
            r.status_code,
            r.duration_ms,
            r.corex_client_id,
            c.display_name AS client_display_name,
            r.broker,
            r.created_at
        FROM request_logs r
        LEFT JOIN corex_clients c
            ON c.corex_client_id = r.corex_client_id
        WHERE r.created_at >= ?
          AND r.created_at <= ?
        ORDER BY r.created_at DESC, r.request_id DESC
        LIMIT ? OFFSET ?
    `).bind(
        range.from,
        range.to,
        limit,
        offset
    ).all();

    return {
        items: rows.results.map(row => ({
            requestId: row.request_id,
            method: row.method,
            path: row.path,
            statusCode: Number(row.status_code),
            durationMs: Number(row.duration_ms),
            clientId: row.corex_client_id,
            clientName: row.client_display_name,
            broker: row.broker,
            createdAt: toIso(row.created_at)
        })),
        period: range.period,
        limit,
        offset
    };
}

export async function getAdminSessions(
    env,
    {
        limit: limitInput,
        status,
        broker,
        apiVersion
    } = {}
) {
    const conditions = [];
    const parameters = [];

    if (status !== undefined && status !== "") {
        if (!DASHBOARD_SESSION_STATUSES.has(status)) {
            throw new TypeError("Invalid session status.");
        }

        conditions.push("s.status = ?");
        parameters.push(status);
    }

    if (broker !== undefined && broker !== "") {
        if (
            typeof broker !== "string" ||
            !/^[a-z0-9_-]{2,32}$/.test(broker)
        ) {
            throw new TypeError("Invalid broker filter.");
        }

        conditions.push("s.broker = ?");
        parameters.push(broker);
    }

    if (apiVersion !== undefined && apiVersion !== "") {
        const version = Number(apiVersion);

        if (![1, 2, 3].includes(version)) {
            throw new TypeError("Invalid API version filter.");
        }

        conditions.push("s.api_version = ?");
        parameters.push(version);
    }

    const where = conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";

    const limit = normalizeLimit(limitInput);

    const rows = await env.DB.prepare(`
        SELECT
            s.session_id,
            s.corex_client_id,
            c.display_name AS client_display_name,
            s.broker,
            s.provider_app_id,
            s.api_version,
            s.status,
            s.created_at,
            s.expires_at,
            s.callback_received_at,
            s.retrieved_at,
            s.code_retrieved_at,
            s.failure_code,
            (s.authorization_code IS NOT NULL) AS has_authorization_code,
            (s.result_ciphertext IS NOT NULL) AS has_result
        FROM auth_sessions s
        LEFT JOIN corex_clients c
            ON c.corex_client_id = s.corex_client_id
        ${where}
        ORDER BY s.created_at DESC, s.session_id DESC
        LIMIT ?
    `).bind(
        ...parameters,
        limit
    ).all();

    return rows.results.map(mapSession);
}

export async function getAdminSession(env, sessionId) {
    const row = await env.DB.prepare(`
        SELECT
            s.session_id,
            s.corex_client_id,
            c.display_name AS client_display_name,
            s.broker,
            s.provider_app_id,
            s.api_version,
            s.status,
            s.created_at,
            s.expires_at,
            s.callback_received_at,
            s.retrieved_at,
            s.code_retrieved_at,
            s.failure_code,
            (s.authorization_code IS NOT NULL) AS has_authorization_code,
            (s.result_ciphertext IS NOT NULL) AS has_result
        FROM auth_sessions s
        LEFT JOIN corex_clients c
            ON c.corex_client_id = s.corex_client_id
        WHERE s.session_id = ?
    `).bind(sessionId).first();

    return row ? mapSession(row) : null;
}

export async function invalidateAdminSession(
    env,
    sessionId,
    actor
) {
    if (typeof actor !== "string" || !actor) {
        throw new TypeError("Invalid administrator identity.");
    }

    const results = await env.DB.batch([
        env.DB.prepare(`
            UPDATE auth_sessions
            SET
                status = 'cancelled',
                authorization_code = NULL,
                result_ciphertext = NULL,
                failure_code = 'admin_invalidated'
            WHERE session_id = ?
              AND api_version = 3
              AND status IN ('pending', 'processing', 'ready')
        `).bind(sessionId),

        env.DB.prepare(`
            INSERT INTO admin_audit (
                id, at, actor, action, target_type, target_id
            )
            SELECT ?, ?, ?, 'session.invalidate', 'session', ?
            WHERE changes() = 1
        `).bind(
            crypto.randomUUID(),
            nowSeconds(),
            actor,
            sessionId
        )
    ]);

    if (results[0]?.meta?.changes === 1) {
        return {
            sessionId,
            status: "cancelled",
            invalidated: true
        };
    }

    const session = await getAdminSession(env, sessionId);

    if (!session) {
        return null;
    }

    return {
        sessionId,
        status: session.status,
        invalidated: false
    };
}