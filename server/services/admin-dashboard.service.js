const BROKERS = new Set(["upstox", "fyers", "zerodha"]);
const SESSION_STATUSES = new Set([
    "pending",
    "code_received",
    "retrieved",
    "failed",
    "expired"
]);

function normalizeLimit(value, fallback = 50) {
    const parsed = Number.parseInt(value, 10);

    if (!Number.isInteger(parsed)) {
        return fallback;
    }

    return Math.max(1, Math.min(parsed, 100));
}

function assertDatabase(env) {
    if (!env.DB) {
        throw new Error("Database binding is missing");
    }
}

export async function getAdminOverview(env, period = "24h") {
    assertDatabase(env);

    const normalizedPeriod = ["24h", "7d", "30d"].includes(period)
        ? period
        : "24h";

    const periodSeconds = {
        "24h": 24 * 60 * 60,
        "7d": 7 * 24 * 60 * 60,
        "30d": 30 * 24 * 60 * 60
    }[normalizedPeriod];

    const now = Math.floor(Date.now() / 1000);
    const startAt = now - periodSeconds;
    const bucketSeconds = periodSeconds / 12;

    const [
        clientStats,
        sessionStatsResult,
        requestStats,
        chartResult
    ] = await Promise.all([
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
            GROUP BY status
        `).all(),

        env.DB.prepare(`
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(
                    CASE WHEN status_code >= 200 AND status_code < 400
                    THEN 1 ELSE 0 END
                ), 0) AS successful,
                COALESCE(SUM(
                    CASE WHEN status_code >= 400
                    THEN 1 ELSE 0 END
                ), 0) AS failed,
                COALESCE(ROUND(AVG(duration_ms)), 0) AS average_latency_ms
            FROM request_logs
            WHERE created_at >= ? AND created_at <= ?
        `).bind(startAt, now).first(),

        env.DB.prepare(`
            SELECT
                CAST((created_at - ?) / ? AS INTEGER) AS bucket,
                COUNT(*) AS total,
                COALESCE(SUM(
                    CASE WHEN status_code >= 200 AND status_code < 400
                    THEN 1 ELSE 0 END
                ), 0) AS successful
            FROM request_logs
            WHERE created_at >= ? AND created_at <= ?
            GROUP BY bucket
        `).bind(startAt, bucketSeconds, startAt, now).all()
    ]);

    const sessions = {
        pending: 0,
        code_received: 0,
        retrieved: 0,
        failed: 0,
        expired: 0
    };

    for (const row of sessionStatsResult.results ?? []) {
        if (SESSION_STATUSES.has(row.status)) {
            sessions[row.status] = Number(row.count);
        }
    }

    sessions.active = sessions.pending + sessions.code_received;
    sessions.total = Object.values(sessions)
        .filter(value => typeof value === "number")
        .reduce((sum, value) => sum + value, 0) - sessions.active;

    // Total sessions are queried separately to avoid derived-count ambiguity.
    const totalSessions = await env.DB.prepare(`
        SELECT COUNT(*) AS total
        FROM auth_sessions
    `).first();

    const totalRequests = Number(requestStats?.total ?? 0);
    const successfulRequests = Number(requestStats?.successful ?? 0);
    const failedRequests = Number(requestStats?.failed ?? 0);

    const chart = Array.from({ length: 12 }, (_, index) => ({
        timestamp: startAt + Math.floor(index * bucketSeconds),
        total: 0,
        successful: 0
    }));

    for (const row of chartResult.results ?? []) {
        const index = Number(row.bucket);

        if (Number.isInteger(index) && index >= 0 && index < chart.length) {
            chart[index].total = Number(row.total);
            chart[index].successful = Number(row.successful);
        }
    }

    return {
        generated_at: now,
        period: normalizedPeriod,

        clients: {
            total: Number(clientStats?.total ?? 0),
            active: Number(clientStats?.active ?? 0),
            revoked: Number(clientStats?.revoked ?? 0)
        },

        sessions: {
            ...sessions,
            total: Number(totalSessions?.total ?? 0)
        },

        requests: {
            total: totalRequests,
            successful: successfulRequests,
            failed: failedRequests,
            success_rate: totalRequests
                ? Math.round(successfulRequests / totalRequests * 1000) / 10
                : 0,
            average_latency_ms: Number(requestStats?.average_latency_ms ?? 0)
        },

        chart
    };
}

export async function getAdminRequests(env, limitInput = 50) {
    assertDatabase(env);

    const limit = normalizeLimit(limitInput);

    const result = await env.DB.prepare(`
        SELECT
            r.request_id,
            r.method,
            r.path,
            r.status_code,
            r.duration_ms,
            r.corex_client_id,
            r.broker,
            r.created_at,
            c.display_name AS client_display_name
        FROM request_logs AS r
        LEFT JOIN corex_clients AS c
            ON c.corex_client_id = r.corex_client_id
        ORDER BY r.created_at DESC
        LIMIT ?
    `).bind(limit).all();

    return result.results ?? [];
}

export async function getAdminClients(
    env,
    { query = "", limit: limitInput = 50 } = {}
) {
    assertDatabase(env);

    const limit = normalizeLimit(limitInput);
    const search = typeof query === "string"
        ? query.trim().slice(0, 80)
        : "";

    const now = Math.floor(Date.now() / 1000);
    const pattern = `%${search}%`;

    const result = await env.DB.prepare(`
        SELECT
            c.corex_client_id,
            c.display_name,
            c.status,
            c.created_at,
            c.last_seen_at,
            (
                SELECT COUNT(*)
                FROM auth_sessions AS s
                WHERE s.corex_client_id = c.corex_client_id
            ) AS session_count,
            (
                SELECT COUNT(*)
                FROM auth_sessions AS s
                WHERE s.corex_client_id = c.corex_client_id
                  AND s.status IN ('pending', 'code_received')
                  AND s.expires_at > ?
            ) AS open_sessions
        FROM corex_clients AS c
        WHERE
            ? = ''
            OR c.display_name LIKE ?
            OR c.corex_client_id LIKE ?
        ORDER BY c.created_at DESC
        LIMIT ?
    `).bind(now, search, pattern, pattern, limit).all();

    return result.results ?? [];
}

export async function getAdminClientDetails(env, clientId) {
    assertDatabase(env);

    const client = await env.DB.prepare(`
        SELECT
            corex_client_id,
            display_name,
            status,
            created_at,
            last_seen_at
        FROM corex_clients
        WHERE corex_client_id = ?
    `).bind(clientId).first();

    if (!client) {
        return null;
    }

    const sessions = await getAdminSessions(env, {
        clientId,
        limit: 20
    });

    return {
        client,
        sessions
    };
}

export async function getAdminSessions(
    env,
    {
        limit: limitInput = 50,
        status = "",
        broker = "",
        clientId = ""
    } = {}
) {
    assertDatabase(env);

    const limit = normalizeLimit(limitInput);
    const conditions = [];
    const parameters = [];

    if (status && SESSION_STATUSES.has(status)) {
        conditions.push("s.status = ?");
        parameters.push(status);
    }

    if (broker && BROKERS.has(broker)) {
        conditions.push("s.broker = ?");
        parameters.push(broker);
    }

    if (clientId) {
        conditions.push("s.corex_client_id = ?");
        parameters.push(clientId);
    }

    const where = conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";

    parameters.push(limit);

    const result = await env.DB.prepare(`
        SELECT
            s.session_id,
            s.corex_client_id,
            c.display_name AS client_display_name,
            s.broker,
            s.provider_app_id,
            s.status,
            s.created_at,
            s.expires_at,
            s.callback_received_at,
            s.code_retrieved_at,
            s.failure_code,
            CASE WHEN s.authorization_code IS NULL
                THEN 0 ELSE 1 END AS has_authorization_code
        FROM auth_sessions AS s
        LEFT JOIN corex_clients AS c
            ON c.corex_client_id = s.corex_client_id
        ${where}
        ORDER BY s.created_at DESC
        LIMIT ?
    `).bind(...parameters).all();

    return result.results ?? [];
}

export async function getAdminSessionDetails(env, sessionId) {
    assertDatabase(env);

    return env.DB.prepare(`
        SELECT
            s.session_id,
            s.corex_client_id,
            c.display_name AS client_display_name,
            c.status AS client_status,
            s.broker,
            s.provider_app_id,
            s.status,
            s.created_at,
            s.expires_at,
            s.callback_received_at,
            s.code_retrieved_at,
            s.failure_code,
            CASE WHEN s.authorization_code IS NULL
                THEN 0 ELSE 1 END AS has_authorization_code
        FROM auth_sessions AS s
        LEFT JOIN corex_clients AS c
            ON c.corex_client_id = s.corex_client_id
        WHERE s.session_id = ?
    `).bind(sessionId).first();
}

export async function invalidateAdminSession(env, sessionId) {
    assertDatabase(env);

    const result = await env.DB.prepare(`
        UPDATE auth_sessions
        SET
            status = 'expired',
            authorization_code = NULL,
            failure_code = 'admin_invalidated'
        WHERE session_id = ?
          AND status IN ('pending', 'code_received')
    `).bind(sessionId).run();

    const session = await getAdminSessionDetails(env, sessionId);

    if (!session) {
        return { outcome: "not_found" };
    }

    if ((result.meta?.changes ?? 0) !== 1) {
        return {
            outcome: "not_active",
            session
        };
    }

    return {
        outcome: "invalidated",
        session
    };
}