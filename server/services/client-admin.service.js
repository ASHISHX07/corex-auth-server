function assertDatabase(env) {
    if (!env?.DB) {
        throw new Error("Database binding is missing.");
    }
}

function assertActor(actor) {
    if (
        typeof actor !== "string" ||
        !actor.trim() ||
        actor.length > 100
    ) {
        throw new Error("Invalid audit actor.");
    }
}

function nowSeconds() {
    return Math.floor(Date.now() / 1000);
}

// Insert an audit event only when the immediately preceding
// database statement actually changed a row.
function createAuditInsert(env, {
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
        SELECT ?, ?, ?, ?, ?, ?
        WHERE changes() = 1
    `).bind(
        crypto.randomUUID(),
        nowSeconds(),
        actor,
        action,
        targetType,
        targetId
    );
}

/* ---------- Client revocation ---------- */

export async function revokeCorexClient(env, clientId, actor) {
    assertDatabase(env);
    assertActor(actor);

    const results = await env.DB.batch([
        // 1. Revoke the client.
        env.DB.prepare(`
            UPDATE corex_clients
            SET status = 'revoked'
            WHERE corex_client_id = ?
              AND status = 'active'
        `).bind(clientId),

        // 2. Audit only if the client was actually revoked.
        createAuditInsert(env, {
            actor,
            action: "client.revoke",
            targetType: "client",
            targetId: clientId
        }),

        // 3. Invalidate its unfinished sessions and remove results.
        env.DB.prepare(`
            UPDATE auth_sessions
            SET
                status = 'expired',
                authorization_code = NULL,
                result_ciphertext = NULL,
                failure_code = 'client_revoked'
            WHERE corex_client_id = ?
              AND status IN (
                  'pending',
                  'code_received',
                  'processing',
                  'ready'
              )
              AND EXISTS (
                  SELECT 1
                  FROM corex_clients
                  WHERE corex_client_id = ?
                    AND status = 'revoked'
              )
        `).bind(clientId, clientId)
    ]);

    const client = await env.DB.prepare(`
        SELECT corex_client_id, status
        FROM corex_clients
        WHERE corex_client_id = ?
    `).bind(clientId).first();

    if (!client) {
        return null;
    }

    return {
        clientId: client.corex_client_id,
        status: client.status,
        expiredSessions: results[2]?.meta?.changes ?? 0
    };
}

/* ---------- Client scope management ---------- */

export async function updateCorexClientScopes(
    env,
    clientId,
    scopes,
    actor
) {
    assertDatabase(env);
    assertActor(actor);

    if (
        !Array.isArray(scopes) ||
        scopes.some(scope => scope !== "auth")
    ) {
        throw new Error("Invalid client scopes.");
    }

    const normalizedScopes = [...new Set(scopes)];
    const scopesJson = JSON.stringify(normalizedScopes);

    const results = await env.DB.batch([
        // 1. Update only when the permissions actually differ.
        env.DB.prepare(`
            UPDATE corex_clients
            SET scopes = ?
            WHERE corex_client_id = ?
              AND scopes != ?
        `).bind(
            scopesJson,
            clientId,
            scopesJson
        ),

        // 2. Audit only when the preceding UPDATE changed a row.
        createAuditInsert(env, {
            actor,
            action: "client.scopes.update",
            targetType: "client",
            targetId: clientId
        })
    ]);

    const client = await env.DB.prepare(`
        SELECT corex_client_id, scopes, status
        FROM corex_clients
        WHERE corex_client_id = ?
    `).bind(clientId).first();

    if (!client) {
        return null;
    }

    return {
        clientId: client.corex_client_id,
        scopes: JSON.parse(client.scopes),
        status: client.status,
        changed: (results[0]?.meta?.changes ?? 0) === 1
    };
}
