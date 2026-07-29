DROP TABLE IF EXISTS embedding_cache;

ALTER TABLE code_chunk
    DROP COLUMN IF EXISTS embedding;
