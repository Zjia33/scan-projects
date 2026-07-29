package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

// 表示审计领域中的 SemanticCallEdge 数据实体。
@Getter
@Setter
@NoArgsConstructor
public class SemanticCallEdge {
    private UUID id; // 语义调用边的唯一标识
    private UUID taskId; // 调用边所属的审计任务 ID
    private UUID callerSymbolId; // 调用方语义符号 ID
    private UUID calleeSymbolId; // 被调用方语义符号 ID，未解析时为空
    private Long callerChunkId; // 调用方所在的代码块 ID
    private Long calleeChunkId; // 被调用方所在的代码块 ID，未解析时为空
    private int callSiteLine; // 调用表达式在调用方文件中的行号
    private String calledName; // 源码中出现的被调用名称
    private String expression; // 原始调用表达式或关系描述
    private String edgeType; // 调用关系类型，如 Java 调用或 MyBatis 映射
    private Confidence confidence; // 调用关系解析的置信度
    private String resolutionReason; // 建立或保留该调用边的解析依据
    private String argumentMapping; // 调用方实参与被调用方形参的映射关系

    // 创建 SemanticCallEdge 实例并初始化所需依赖或状态。
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
