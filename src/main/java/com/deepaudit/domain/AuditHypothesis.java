package com.deepaudit.domain;

import java.time.Instant;
import java.util.UUID;

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
    private String criticReason;
    private Instant createdAt;
    private Instant updatedAt;

    public AuditHypothesis() {
    }

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

    public UUID getId() { return id; }
    public UUID getTaskId() { return taskId; }
    public UUID getRunId() { return runId; }
    public VulnerabilityType getType() { return type; }
    public HypothesisStatus getStatus() { return status; }
    public String getClaim() { return claim; }
    public Long getPrimaryChunkId() { return primaryChunkId; }
    public String getEvidenceChunkIds() { return evidenceChunkIds; }
    public Confidence getConfidence() { return confidence; }
    public String getCriticReason() { return criticReason; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setId(UUID id) { this.id = id; }
    public void setTaskId(UUID taskId) { this.taskId = taskId; }
    public void setRunId(UUID runId) { this.runId = runId; }
    public void setType(VulnerabilityType type) { this.type = type; }
    public void setStatus(HypothesisStatus status) { this.status = status; }
    public void setClaim(String claim) { this.claim = claim; }
    public void setPrimaryChunkId(Long primaryChunkId) { this.primaryChunkId = primaryChunkId; }
    public void setEvidenceChunkIds(String evidenceChunkIds) { this.evidenceChunkIds = evidenceChunkIds; }
    public void setConfidence(Confidence confidence) { this.confidence = confidence; }
    public void setCriticReason(String criticReason) { this.criticReason = criticReason; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
