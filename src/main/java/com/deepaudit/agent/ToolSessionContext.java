package com.deepaudit.agent;

import java.util.Set;

/** 当前调查中已验证证据与可读取候选的最小会话状态。 */
public record ToolSessionContext(Long rootChunkId, Set<Long> allowedEvidenceChunkIds,
                                 Set<Long> candidateChunkIds) {
    public ToolSessionContext {
        allowedEvidenceChunkIds = allowedEvidenceChunkIds == null
                ? Set.of() : Set.copyOf(allowedEvidenceChunkIds);
        candidateChunkIds = candidateChunkIds == null ? Set.of() : Set.copyOf(candidateChunkIds);
    }

    boolean canRead(Long chunkId) {
        return chunkId != null && (allowedEvidenceChunkIds.contains(chunkId)
                || candidateChunkIds.contains(chunkId));
    }
}
