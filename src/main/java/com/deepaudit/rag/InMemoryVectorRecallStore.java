package com.deepaudit.rag;

import com.deepaudit.domain.CodeChunk;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;

/**
 * 仅供 H2 和单元测试使用的向量召回实现，生产配置不启用。
 */
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "deepaudit.vector-store.provider", havingValue = "memory")
public class InMemoryVectorRecallStore implements VectorRecallStore {

    private final EmbeddingService embeddingService;

    @Override
    public void synchronizeTask(UUID taskId) {
        // 内存实现直接读取 CodeChunk 中的序列化向量，不需要额外同步。
    }

    @Override
    public List<VectorMatch> search(List<CodeChunk> chunks, UUID taskId, Long excludedChunkId,
                                    double[] queryVector, int limit) {
        return chunks.stream()
                .filter(chunk -> chunk.getId() != null)
                .filter(chunk -> taskId == null || taskId.equals(chunk.getTaskId()))
                .filter(chunk -> excludedChunkId == null || !excludedChunkId.equals(chunk.getId()))
                .filter(chunk -> chunk.getEmbedding() != null && !chunk.getEmbedding().isBlank())
                .map(chunk -> new VectorMatch(chunk.getId(),
                        cosine(queryVector, embeddingService.deserialize(chunk.getEmbedding()))))
                .sorted(Comparator.comparingDouble(VectorMatch::cosineSimilarity).reversed())
                .limit(limit)
                .toList();
    }

    private double cosine(double[] left, double[] right) {
        int length = Math.min(left.length, right.length);
        double dot = 0;
        double leftNorm = 0;
        double rightNorm = 0;
        for (int index = 0; index < length; index++) {
            dot += left[index] * right[index];
            leftNorm += left[index] * left[index];
            rightNorm += right[index] * right[index];
        }
        if (leftNorm == 0 || rightNorm == 0) return 0;
        return dot / (Math.sqrt(leftNorm) * Math.sqrt(rightNorm));
    }
}
