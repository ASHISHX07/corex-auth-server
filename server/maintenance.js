const DAY = 86400;

const REQUEST_LOG_RETENTION = 30 * DAY;
const SESSION_RETENTION = 90 * DAY;
const AUDIT_RETENTION = 365 * DAY;

export async function runMaintenance(
    env,
    now = Math.floor(Date.now() / 1000)
) {
    if (!env?.DB) {
        throw new Error("Database binding is missing.");
    }

    return env.DB.batch([
        // Expire unfinished and failed sessions when their lifetime ends.
        // Also wipe any leftover authorization codes and ciphertext.
        env.DB.prepare(`
            UPDATE auth_sessions
            SET
                status = CASE
                    WHEN status IN (
                        'pending',
                        'code_received',
                        'processing',
                        'ready',
                        'failed'
                    )
                    THEN 'expired'
                    ELSE status
                END,

                authorization_code = NULL,
                result_ciphertext = NULL,

                failure_code = CASE
                    WHEN status IN (
                        'pending',
                        'code_received',
                        'processing',
                        'ready',
                        'failed'
                    )
                    THEN 'session_expired'
                    ELSE failure_code
                END

            WHERE expires_at <= ?
              AND (
                  status IN (
                      'pending',
                      'code_received',
                      'processing',
                      'ready',
                      'failed'
                  )
                  OR authorization_code IS NOT NULL
                  OR result_ciphertext IS NOT NULL
              )
        `).bind(now),

        // Request metadata is retained for 30 days.
        env.DB.prepare(`
            DELETE FROM request_logs
            WHERE created_at < ?
        `).bind(now - REQUEST_LOG_RETENTION),

        // Terminal sessions are retained for 90 days.
        env.DB.prepare(`
            DELETE FROM auth_sessions
            WHERE status IN (
                'retrieved',
                'failed',
                'expired',
                'cancelled'
            )
            AND created_at < ?
        `).bind(now - SESSION_RETENTION),

        // Administrative audit records are retained for one year.
        env.DB.prepare(`
            DELETE FROM admin_audit
            WHERE at < ?
        `).bind(now - AUDIT_RETENTION)
    ]);
}