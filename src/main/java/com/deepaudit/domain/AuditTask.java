package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class AuditTask {

    private UUID id;
    private UUID projectId;
    private AuditStatus status;
    private int progress;
    private String currentStage;
    private String errorMessage;
    private ScanMode scanMode;
    private String baseCommitSha;
    private String targetCommitSha;
    private String mergeBaseSha;
    private String changeSummary;
    private Instant createdAt;
    private Instant completedAt;
    private long version;

    public AuditTask(UUID projectId) {
        this(projectId, ScanMode.FULL, null, null, null);
    }

    public AuditTask(UUID projectId, ScanMode scanMode, String baseCommitSha,
                     String targetCommitSha, String mergeBaseSha) {
        this.id = UUID.randomUUID();
        this.projectId = projectId;
        this.scanMode = scanMode == null ? ScanMode.FULL : scanMode;
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
        if (status == AuditStatus.COMPLETED || status == AuditStatus.FAILED || status == AuditStatus.CANCELLED) {
            this.completedAt = Instant.now();
        }
    }

    public void fail(String message) {
        this.errorMessage = message == null ? "未知扫描错误" : message.substring(0, Math.min(message.length(), 2000));
        moveTo(AuditStatus.FAILED, progress, "扫描失败");
    }

}
