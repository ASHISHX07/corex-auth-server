export async function revokeCorexClient(env, clientId) {
    if (!env.DB) {
        throw new Error("Database binding is missing");
    }

    // D1 batch runs these statements in one transaction.
    const results = await env.DB.batch([
        env.DB.prepare(`
            UPDATE corex_clients
            SET status = 'revoked'
            WHERE corex_client_id = ?
              AND status = 'active'
        `).bind(clientId),

        env.DB.prepare(`
            UPDATE auth_sessions
            SET
                status = 'expired',
                authorization_code = NULL,
                failure_code = 'client_revoked'
            WHERE corex_client_id = ?
              AND status IN ('pending', 'code_received')
              AND EXISTS (
                  SELECT 1
                  FROM corex_clients
                  WHERE corex_client_id = ?
                    AND status = 'revoked'
              )
        `).bind(clientId, clientId)
    ]);

    const client = await env.DB
        .prepare(`
            SELECT corex_client_id, status
            FROM corex_clients
            WHERE corex_client_id = ?
        `)
        .bind(clientId)
        .first();

    if (!client) {
        return null;
    }

    return {
        clientId: client.corex_client_id,
        status: client.status,
        expiredSessions: results[1]?.meta?.changes ?? 0
    };
}