DROP INDEX IF EXISTS idx_code_chunk_embedding_hnsw;

ALTER TABLE code_chunk
    DROP COLUMN IF EXISTS embedding_vector;

-- vector 扩展是数据库级共享对象，不能由应用迁移擅自删除。
