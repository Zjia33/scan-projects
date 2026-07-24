package com.deepaudit.rag;

import com.deepaudit.domain.CodeChunk;

import java.util.List;
import java.util.UUID;

/**
 * 向量召回存储抽象：生产环境由 pgvector 执行近邻查询，测试环境使用确定性内存实现。
 */
public interface VectorRecallStore {

    /**
     * 将代码块中已生成的序列化向量同步到当前存储的可检索向量列。
     */
    void synchronizeTask(UUID taskId);

    /**
     * 按余弦相似度召回候选代码块，不在这里混入关键词或结构关系分数。
     */
    List<VectorMatch> search(List<CodeChunk> chunks, UUID taskId, Long excludedChunkId,
                             double[] queryVector, int limit);

    record VectorMatch(long chunkId, double cosineSimilarity) {
    }
}
