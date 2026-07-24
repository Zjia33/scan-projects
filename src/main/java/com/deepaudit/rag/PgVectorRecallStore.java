package com.deepaudit.rag;

import com.deepaudit.domain.CodeChunk;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * 使用 PostgreSQL pgvector 的 HNSW 索引执行数据库侧余弦近邻召回。
 */
@Component
@ConditionalOnProperty(name = "deepaudit.vector-store.provider", havingValue = "pgvector", matchIfMissing = true)
public class PgVectorRecallStore implements VectorRecallStore {

    private final JdbcTemplate jdbcTemplate;
    private final int dimensions;
    private final int efSearch;

    public PgVectorRecallStore(JdbcTemplate jdbcTemplate,
                               @Value("${deepaudit.embedding.dimensions:1024}") int dimensions,
                               @Value("${deepaudit.vector-store.hnsw-ef-search:100}") int efSearch) {
        if (dimensions < 1 || dimensions > 2_000) {
            throw new IllegalArgumentException("pgvector vector/HNSW 维度必须在 1 到 2000 之间");
        }
        this.jdbcTemplate = jdbcTemplate;
        this.dimensions = dimensions;
        this.efSearch = Math.max(1, efSearch);
    }

    @Override
    @Transactional
    public void synchronizeTask(UUID taskId) {
        List<Long> invalidChunks = jdbcTemplate.query("""
                        SELECT id
                        FROM code_chunk
                        WHERE task_id = ?
                          AND embedding IS NOT NULL
                          AND btrim(embedding) <> ''
                          AND cardinality(string_to_array(embedding, ',')) <> ?
                        LIMIT 1
                        """,
                (resultSet, rowNumber) -> resultSet.getLong("id"), taskId, dimensions);
        if (!invalidChunks.isEmpty()) {
            throw new IllegalStateException("代码块 " + invalidChunks.get(0)
                    + " 的 Embedding 维度与 deepaudit.embedding.dimensions=" + dimensions + " 不一致");
        }

        jdbcTemplate.update("""
                UPDATE code_chunk
                SET embedding_vector = CASE
                    WHEN embedding IS NULL OR btrim(embedding) = '' THEN NULL
                    ELSE CAST('[' || embedding || ']' AS vector)
                END
                WHERE task_id = ?
                """, taskId);
    }

    @Override
    @Transactional(readOnly = true)
    public List<VectorMatch> search(List<CodeChunk> chunks, UUID taskId, Long excludedChunkId,
                                    double[] queryVector, int limit) {
        validateDimensions(queryVector);
        String vectorLiteral = vectorLiteral(queryVector);
        // 提高 HNSW 查询候选宽度，在按 task_id 过滤时保持更稳定的召回率。
        jdbcTemplate.queryForObject("SELECT set_config('hnsw.ef_search', ?, true)",
                String.class, Integer.toString(efSearch));
        jdbcTemplate.queryForObject("SELECT set_config('hnsw.iterative_scan', 'strict_order', true)",
                String.class);

        StringBuilder sql = new StringBuilder("""
                SELECT id, 1 - (embedding_vector <=> CAST(? AS vector)) AS cosine_similarity
                FROM code_chunk
                WHERE task_id = ?
                  AND embedding_vector IS NOT NULL
                """);
        List<Object> parameters = new ArrayList<>();
        parameters.add(vectorLiteral);
        parameters.add(taskId);
        if (excludedChunkId != null) {
            sql.append(" AND id <> ?");
            parameters.add(excludedChunkId);
        }
        sql.append(" ORDER BY embedding_vector <=> CAST(? AS vector) LIMIT ?");
        parameters.add(vectorLiteral);
        parameters.add(limit);

        return jdbcTemplate.query(sql.toString(),
                (resultSet, rowNumber) -> new VectorMatch(
                        resultSet.getLong("id"), resultSet.getDouble("cosine_similarity")),
                parameters.toArray());
    }

    private void validateDimensions(double[] vector) {
        if (vector.length != dimensions) {
            throw new IllegalStateException("查询 Embedding 实际维度为 " + vector.length
                    + "，但 pgvector 列配置维度为 " + dimensions);
        }
    }

    private String vectorLiteral(double[] vector) {
        if (Arrays.stream(vector).anyMatch(value -> !Double.isFinite(value))) {
            throw new IllegalArgumentException("Embedding 包含非有限数值，不能写入 pgvector");
        }
        return Arrays.stream(vector)
                .mapToObj(Double::toString)
                .collect(Collectors.joining(",", "[", "]"));
    }
}
