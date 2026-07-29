package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

// 表示审计领域中的 AuditHypothesis 数据实体。
@Getter
@Setter
@NoArgsConstructor
public class AuditHypothesis {
    private UUID id; // 漏洞假设的唯一标识
    private UUID taskId; // 假设所属的审计任务 ID
    private UUID runId; // 提出假设的 Agent 运行 ID
    private VulnerabilityType type; // 假设对应的漏洞类型
    private HypothesisStatus status; // 假设在调查与评审流程中的状态
    private String claim; // 专业 Agent 提出的可验证安全主张
    private Long primaryChunkId; // 假设聚焦的主代码块 ID
    private String evidenceChunkIds; // 支撑假设的代码块 ID 集合序列化文本
    private Confidence confidence; // Agent 对假设成立程度的置信度
    private String criticReason; // Critic 确认或驳回假设的理由
    private Instant createdAt; // 假设创建时间
    private Instant updatedAt; // 假设状态最后更新时间

    // 创建 AuditHypothesis 实例并初始化所需依赖或状态。
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
