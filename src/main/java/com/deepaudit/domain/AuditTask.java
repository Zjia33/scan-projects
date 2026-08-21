package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

// 表示审计领域中的 AuditTask 数据实体。
@Getter
@Setter
@NoArgsConstructor
public class AuditTask {

    private UUID id; // 审计任务的唯一标识
    private UUID projectId; // 任务所属的项目 ID
    private AuditStatus status; // 任务当前所处的处理状态
    private int progress; // 任务整体进度百分比
    private String currentStage; // 前端展示的当前处理阶段说明
    private String errorMessage; // 任务失败时记录的错误摘要
    private String baseCommitSha; // 增量扫描用于对比的基线提交哈希
    private String targetCommitSha; // 本次扫描目标提交的哈希
    private String mergeBaseSha; // 基线与目标提交的最近公共祖先哈希
    private String changeSummary; // 增量差异及深度分析范围摘要
    private Instant createdAt; // 任务创建时间
    private Instant completedAt; // 任务进入终态的时间
    private long version; // 乐观锁版本号，防止并发状态覆盖

    public AuditTask(UUID projectId) {
        this(projectId, null, null, null);
    }

    public AuditTask(UUID projectId, String baseCommitSha,
                     String targetCommitSha, String mergeBaseSha) {
        this.id = UUID.randomUUID();
        this.projectId = projectId;
        this.baseCommitSha = baseCommitSha;
        this.targetCommitSha = targetCommitSha;
        this.mergeBaseSha = mergeBaseSha;
        this.status = AuditStatus.UPLOADED;
        this.progress = 0;
        this.currentStage = "等待扫描";
        this.createdAt = Instant.now();
    }

    public void moveTo(AuditStatus status, int progress, String currentStage) {
        this.status = status;
        this.progress = progress;
        this.currentStage = currentStage;
        if (status.isTerminal()) {
            this.completedAt = Instant.now();
        }
    }

    public void fail(String message) {
        this.errorMessage = message == null ? "未知扫描错误" : message.substring(0, Math.min(message.length(), 2000));
        moveTo(AuditStatus.FAILED, progress, "扫描失败");
    }

}
