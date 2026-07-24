CREATE EXTENSION IF NOT EXISTS vector;

ALTER TABLE code_chunk
    ADD COLUMN embedding_vector vector(${embeddingDimensions});

COMMENT ON COLUMN code_chunk.embedding_vector IS
    '用于 pgvector 余弦近邻召回；维度必须与当前 Embedding 模型一致';

UPDATE code_chunk
SET embedding_vector = CAST('[' || embedding || ']' AS vector)
WHERE embedding IS NOT NULL
  AND btrim(embedding) <> ''
  AND cardinality(string_to_array(embedding, ',')) = ${embeddingDimensions};

CREATE INDEX idx_code_chunk_embedding_hnsw
    ON code_chunk USING hnsw (embedding_vector vector_cosine_ops);
