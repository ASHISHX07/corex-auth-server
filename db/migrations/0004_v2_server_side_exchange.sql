-- v2: server-side token exchange.
-- Rebuilds auth_sessions to (a) make the v1-only columns nullable, (b) drop the
-- hard-coded broker CHECK so adding a broker never needs a migration, and
-- (c) add result_ciphertext + api_version. Existing v1 rows are preserved.
CREATE TABLE auth_sessions_new (
    session_id TEXT PRIMARY KEY,
    corex_client_id TEXT REFERENCES corex_clients(corex_client_id),
    broker TEXT NOT NULL CHECK (length(broker) BETWEEN 2 AND 32),
    provider_app_id TEXT NOT NULL,
    api_version INTEGER NOT NULL DEFAULT 1 CHECK (api_version IN (1, 2)),

    -- v1 only (NULL for v2 sessions; v2 state is a sealed, stateless blob)
    state_hash TEXT UNIQUE,
    retrieval_secret_hash TEXT,
    authorization_code TEXT,

    -- v2 only: result encrypted to the client's public key. Never plaintext.
    result_ciphertext TEXT,

    status TEXT NOT NULL
        CHECK (status IN ('pending','code_received','retrieved','failed','expired')),

    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    callback_received_at INTEGER,
    code_retrieved_at INTEGER,
    failure_code TEXT,

    CHECK (expires_at > created_at)
);

INSERT INTO auth_sessions_new (
    session_id, corex_client_id, broker, provider_app_id, api_version,
    state_hash, retrieval_secret_hash, authorization_code, status,
    created_at, expires_at, callback_received_at, code_retrieved_at, failure_code
)
SELECT
    session_id, corex_client_id, broker, provider_app_id, 1,
    state_hash, retrieval_secret_hash, authorization_code, status,
    created_at, expires_at, callback_received_at, code_retrieved_at, failure_code
FROM auth_sessions;

DROP TABLE auth_sessions;
ALTER TABLE auth_sessions_new RENAME TO auth_sessions;

CREATE INDEX idx_auth_sessions_status_expiry ON auth_sessions (status, expires_at);
CREATE INDEX idx_auth_sessions_client ON auth_sessions (corex_client_id, created_at);
