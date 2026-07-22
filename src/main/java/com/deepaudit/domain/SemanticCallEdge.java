package com.deepaudit.domain;

import java.util.UUID;

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

    public SemanticCallEdge() {}

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

    public UUID getId() { return id; }
    public UUID getTaskId() { return taskId; }
    public UUID getCallerSymbolId() { return callerSymbolId; }
    public UUID getCalleeSymbolId() { return calleeSymbolId; }
    public Long getCallerChunkId() { return callerChunkId; }
    public Long getCalleeChunkId() { return calleeChunkId; }
    public int getCallSiteLine() { return callSiteLine; }
    public String getCalledName() { return calledName; }
    public String getExpression() { return expression; }
    public String getEdgeType() { return edgeType; }
    public Confidence getConfidence() { return confidence; }
    public String getResolutionReason() { return resolutionReason; }
    public String getArgumentMapping() { return argumentMapping; }
    public void setId(UUID id) { this.id = id; }
    public void setTaskId(UUID taskId) { this.taskId = taskId; }
    public void setCallerSymbolId(UUID callerSymbolId) { this.callerSymbolId = callerSymbolId; }
    public void setCalleeSymbolId(UUID calleeSymbolId) { this.calleeSymbolId = calleeSymbolId; }
    public void setCallerChunkId(Long callerChunkId) { this.callerChunkId = callerChunkId; }
    public void setCalleeChunkId(Long calleeChunkId) { this.calleeChunkId = calleeChunkId; }
    public void setCallSiteLine(int callSiteLine) { this.callSiteLine = callSiteLine; }
    public void setCalledName(String calledName) { this.calledName = calledName; }
    public void setExpression(String expression) { this.expression = expression; }
    public void setEdgeType(String edgeType) { this.edgeType = edgeType; }
    public void setConfidence(Confidence confidence) { this.confidence = confidence; }
    public void setResolutionReason(String resolutionReason) { this.resolutionReason = resolutionReason; }
    public void setArgumentMapping(String argumentMapping) { this.argumentMapping = argumentMapping; }
}
