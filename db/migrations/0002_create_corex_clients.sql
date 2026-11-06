-- Migration number: 0002 	 2026-10-20T13:46:12.765Z
CREATE TABLE corex_clients (
    corex_client_id TEXT PRIMARY KEY,

    api_key_hash TEXT NOT NULL UNIQUE,

    display_name TEXT NOT NULL,

    status TEXT NOT NULL
        CHECK (status IN ( 'active', 'revoked' )),

    created_at INTEGER NOT NULL,
    last_seen_at INTEGER
);

ALTER TABLE auth_sessions
ADD COLUMN corex_client_id TEXT
REFERENCES corex_clients(corex_client_id);

CREATE INDEX idx_auth_sessions_client
    ON auth_sessions (corex_client_id, created_at);