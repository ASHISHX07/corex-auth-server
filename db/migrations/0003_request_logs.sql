CREATE TABLE request_logs (
    request_id TEXT PRIMARY KEY,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
    corex_client_id TEXT,
    broker TEXT,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_request_logs_created_at
    ON request_logs (created_at DESC);

CREATE INDEX idx_request_logs_status_created
    ON request_logs (status_code, created_at DESC);

CREATE INDEX idx_request_logs_client_created
    ON request_logs (corex_client_id, created_at DESC);