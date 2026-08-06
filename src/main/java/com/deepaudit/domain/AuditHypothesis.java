package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/** 专业 Agent 调查期间形成的可验证安全假设。 */
@Getter
@Setter
@NoArgsConstructor
public class AuditHypothesis {
    private UUID id;
    private UUID taskId;
    private UUID runId;
    private VulnerabilityType type;
    private HypothesisStatus status;
    private String claim;
    private Long primaryChunkId;
    private String evidenceChunkIds;
    private Confidence confidence;
    private String validationReason;
    private Instant createdAt;
    private Instant updatedAt;

    public AuditHypothesis(UUID taskId, UUID runId, VulnerabilityType type, String claim,
                           Long primaryChunkId, String evidenceChunkIds, Confidence confidence) {
        this.id = UUID.randomUUID();
        this.taskId = taskId;
        this.runId = runId;
        this.type = type;
        this.status = HypothesisStatus.SUPPORTED;
        this.claim = claim;
        this.primaryChunkId = primaryChunkId;
        this.evidenceChunkIds = evidenceChunkIds;
        this.confidence = confidence;
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
    }
}
