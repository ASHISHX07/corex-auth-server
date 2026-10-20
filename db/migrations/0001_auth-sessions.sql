-- Migration number: 0001 	 2026-10-20T06:56:21.394Z
CREATE TABLE auth_sessions (
    session_id TEXT PRIMARY KEY,

    client_id TEXT NOT NULL,

    state_hash TEXT NOT NULL UNIQUE,
    retrieval_secret_hash TEXT NOT NULL,

    status TEXT NOT NULL
        CHECK (
            status IN (
                'pending',
                'code_received',
                'retrieved',
                'failed',
                'expired'
            )
        ),

    authorization_code TEXT,

    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,

    callback_received_at INTEGER,
    code_retrieved_at INTEGER,

    failure_code TEXT,

    CHECK (expires_at > created_at)
);

CREATE INDEX idx_auth_sessions_status_expiry
    ON auth_sessions (status, expires_at);