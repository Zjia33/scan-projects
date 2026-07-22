package com.deepaudit.domain;

import java.util.UUID;

public class SecurityFlow {
    private UUID id;
    private UUID taskId;
    private VulnerabilityType type;
    private UUID sourceSymbolId;
    private UUID sinkSymbolId;
    private Long primaryChunkId;
    private String sourceDescription;
    private String sinkDescription;
    private String guardSummary;
    private String pathText;
    private String evidenceChunkIds;
    private Confidence confidence;
    private int resolvedEdges;
    private int unresolvedEdges;

    public SecurityFlow() {}

    public SecurityFlow(UUID taskId, VulnerabilityType type, UUID sourceSymbolId, UUID sinkSymbolId,
                        Long primaryChunkId, String sourceDescription, String sinkDescription,
                        String guardSummary, String pathText, String evidenceChunkIds,
                        Confidence confidence, int resolvedEdges, int unresolvedEdges) {
        this.id = UUID.randomUUID();
        this.taskId = taskId;
        this.type = type;
        this.sourceSymbolId = sourceSymbolId;
        this.sinkSymbolId = sinkSymbolId;
        this.primaryChunkId = primaryChunkId;
        this.sourceDescription = sourceDescription;
        this.sinkDescription = sinkDescription;
        this.guardSummary = guardSummary;
        this.pathText = pathText;
        this.evidenceChunkIds = evidenceChunkIds;
        this.confidence = confidence;
        this.resolvedEdges = resolvedEdges;
        this.unresolvedEdges = unresolvedEdges;
    }

    public UUID getId() { return id; }
    public UUID getTaskId() { return taskId; }
    public VulnerabilityType getType() { return type; }
    public UUID getSourceSymbolId() { return sourceSymbolId; }
    public UUID getSinkSymbolId() { return sinkSymbolId; }
    public Long getPrimaryChunkId() { return primaryChunkId; }
    public String getSourceDescription() { return sourceDescription; }
    public String getSinkDescription() { return sinkDescription; }
    public String getGuardSummary() { return guardSummary; }
    public String getPathText() { return pathText; }
    public String getEvidenceChunkIds() { return evidenceChunkIds; }
    public Confidence getConfidence() { return confidence; }
    public int getResolvedEdges() { return resolvedEdges; }
    public int getUnresolvedEdges() { return unresolvedEdges; }
    public void setId(UUID id) { this.id = id; }
    public void setTaskId(UUID taskId) { this.taskId = taskId; }
    public void setType(VulnerabilityType type) { this.type = type; }
    public void setSourceSymbolId(UUID sourceSymbolId) { this.sourceSymbolId = sourceSymbolId; }
    public void setSinkSymbolId(UUID sinkSymbolId) { this.sinkSymbolId = sinkSymbolId; }
    public void setPrimaryChunkId(Long primaryChunkId) { this.primaryChunkId = primaryChunkId; }
    public void setSourceDescription(String sourceDescription) { this.sourceDescription = sourceDescription; }
    public void setSinkDescription(String sinkDescription) { this.sinkDescription = sinkDescription; }
    public void setGuardSummary(String guardSummary) { this.guardSummary = guardSummary; }
    public void setPathText(String pathText) { this.pathText = pathText; }
    public void setEvidenceChunkIds(String evidenceChunkIds) { this.evidenceChunkIds = evidenceChunkIds; }
    public void setConfidence(Confidence confidence) { this.confidence = confidence; }
    public void setResolvedEdges(int resolvedEdges) { this.resolvedEdges = resolvedEdges; }
    public void setUnresolvedEdges(int unresolvedEdges) { this.unresolvedEdges = unresolvedEdges; }
}
