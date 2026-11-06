-- Client metadata and permissions.
ALTER TABLE corex_clients
ADD COLUMN key_hint TEXT;

ALTER TABLE corex_clients
ADD COLUMN scopes TEXT NOT NULL DEFAULT '["auth"]';

ALTER TABLE corex_clients
ADD COLUMN created_by TEXT;


-- Rebuild auth_sessions to support V3 while retaining V1/V2 columns.
CREATE TABLE auth_sessions_new (
    session_id TEXT PRIMARY KEY,
    corex_client_id TEXT REFERENCES corex_clients(corex_client_id),

    broker TEXT NOT NULL
        CHECK (length(broker) BETWEEN 2 AND 32),

    provider_app_id TEXT NOT NULL,

    api_version INTEGER NOT NULL DEFAULT 1
        CHECK (api_version IN (1, 2, 3)),

    -- Legacy V1/V2 columns. Retained until migration 0006.
    state_hash TEXT UNIQUE,
    retrieval_secret_hash TEXT,
    authorization_code TEXT,

    -- V2 encrypted envelope / V3 encrypted token at rest.
    result_ciphertext TEXT,

    status TEXT NOT NULL CHECK (
        status IN (
            'pending',
            'code_received',
            'processing',
            'ready',
            'retrieved',
            'failed',
            'expired',
            'cancelled'
        )
    ),

    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,

    callback_received_at INTEGER,

    -- Legacy V1/V2 timestamp.
    code_retrieved_at INTEGER,

    -- V3 retrieval timestamp.
    retrieved_at INTEGER,

    failure_code TEXT,

    CHECK (expires_at > created_at)
);


-- Expire unfinished V1/V2 sessions during the migration.
-- Remove any legacy codes and ciphertext.
INSERT INTO auth_sessions_new (
    session_id,
    corex_client_id,
    broker,
    provider_app_id,
    api_version,
    state_hash,
    retrieval_secret_hash,
    authorization_code,
    result_ciphertext,
    status,
    created_at,
    expires_at,
    callback_received_at,
    code_retrieved_at,
    retrieved_at,
    failure_code
)
SELECT
    session_id,
    corex_client_id,
    broker,
    provider_app_id,
    api_version,
    state_hash,
    retrieval_secret_hash,
    NULL,
    NULL,
    CASE
        WHEN api_version IN (1, 2)
         AND status IN ('pending', 'code_received')
        THEN 'expired'
        ELSE status
    END,
    created_at,
    expires_at,
    callback_received_at,
    code_retrieved_at,
    NULL,
    CASE
        WHEN api_version IN (1, 2)
         AND status IN ('pending', 'code_received')
        THEN 'session_expired'
        ELSE failure_code
    END
FROM auth_sessions;

DROP TABLE auth_sessions;

ALTER TABLE auth_sessions_new
RENAME TO auth_sessions;

CREATE INDEX idx_auth_sessions_status_expiry
ON auth_sessions (status, expires_at);

CREATE INDEX idx_auth_sessions_client
ON auth_sessions (corex_client_id, created_at);


-- Admin mutation history.
CREATE TABLE admin_audit (
    id TEXT PRIMARY KEY,
    at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL
);

CREATE INDEX idx_admin_audit_at
ON admin_audit (at DESC);