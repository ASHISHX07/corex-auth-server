const DAY = 86400;
const REQUEST_LOG_RETENTION_DAYS = 30;
const SESSION_RETENTION_DAYS = 90;

/**
 * Runs from the Cron Trigger. Keeps D1 small (free-tier friendly) and makes sure
 * no result ciphertext or v1 authorization code outlives its session.
 */
export async function runMaintenance(env) {
    const now = Math.floor(Date.now() / 1000);

    await env.DB.batch([
        env.DB.prepare(`
            UPDATE auth_sessions
            SET status = 'expired', authorization_code = NULL,
                result_ciphertext = NULL, failure_code = 'session_expired'
            WHERE status IN ('pending', 'code_received') AND expires_at <= ?
        `).bind(now),

        env.DB.prepare(`DELETE FROM request_logs WHERE created_at < ?`)
            .bind(now - REQUEST_LOG_RETENTION_DAYS * DAY),

        env.DB.prepare(`
            DELETE FROM auth_sessions
            WHERE status IN ('retrieved', 'failed', 'expired') AND created_at < ?
        `).bind(now - SESSION_RETENTION_DAYS * DAY)
    ]);
}
