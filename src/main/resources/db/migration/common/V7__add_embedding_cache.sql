CREATE TABLE embedding_cache (
    cache_key VARCHAR(64) PRIMARY KEY,
    embedding TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);
