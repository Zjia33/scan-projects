package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
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

}
