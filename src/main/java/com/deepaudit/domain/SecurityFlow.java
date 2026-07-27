package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class SecurityFlow {
    private UUID id; // 语义安全流的唯一标识
    private UUID taskId; // 安全流所属的审计任务 ID
    private VulnerabilityType type; // 安全流提示的候选漏洞类型
    private UUID sourceSymbolId; // 不可信数据来源对应的语义符号 ID
    private UUID sinkSymbolId; // 危险操作终点对应的语义符号 ID
    private Long primaryChunkId; // 安全流首要调查的代码块 ID
    private String sourceDescription; // 数据来源及其安全意义说明
    private String sinkDescription; // 危险终点及其安全影响说明
    private String guardSummary; // 路径上已识别的校验或授权保护摘要
    private String pathText; // 从来源到终点的可读调用路径
    private String evidenceChunkIds; // 路径所覆盖代码块 ID 的序列化文本
    private Confidence confidence; // 语义解析结果的置信度
    private int resolvedEdges; // 路径中已成功解析的调用边数量
    private int unresolvedEdges; // 路径中未能解析的调用边数量

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
