package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class SemanticCallEdge {
    private UUID id;
    private UUID taskId;
    private UUID callerSymbolId;
    private UUID calleeSymbolId;
    private Long callerChunkId;
    private Long calleeChunkId;
    private int callSiteLine;
    private String calledName;
    private String expression;
    private String edgeType;
    private Confidence confidence;
    private String resolutionReason;
    private String argumentMapping;

    public SemanticCallEdge(UUID taskId, UUID callerSymbolId, UUID calleeSymbolId,
                            Long callerChunkId, Long calleeChunkId, int callSiteLine,
                            String calledName, String expression, String edgeType,
                            Confidence confidence, String resolutionReason, String argumentMapping) {
        this.id = UUID.randomUUID();
        this.taskId = taskId;
        this.callerSymbolId = callerSymbolId;
        this.calleeSymbolId = calleeSymbolId;
        this.callerChunkId = callerChunkId;
        this.calleeChunkId = calleeChunkId;
        this.callSiteLine = callSiteLine;
        this.calledName = calledName;
        this.expression = expression;
        this.edgeType = edgeType;
        this.confidence = confidence;
        this.resolutionReason = resolutionReason;
        this.argumentMapping = argumentMapping == null ? "" : argumentMapping;
    }

}
