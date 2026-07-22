package com.deepaudit.domain;

import java.time.Instant;
import java.util.UUID;

public class AuditTask {

    private UUID id;
    private UUID projectId;
    private AuditStatus status;
    private int progress;
    private String currentStage;
    private String errorMessage;
    private Instant createdAt;
    private Instant completedAt;
    private long version;

    public AuditTask() {
    }

    public AuditTask(UUID projectId) {
        this.id = UUID.randomUUID();
        this.projectId = projectId;
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

    public UUID getId() { return id; }
    public UUID getProjectId() { return projectId; }
    public AuditStatus getStatus() { return status; }
    public int getProgress() { return progress; }
    public String getCurrentStage() { return currentStage; }
    public String getErrorMessage() { return errorMessage; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getCompletedAt() { return completedAt; }
    public long getVersion() { return version; }
    public void setId(UUID id) { this.id = id; }
    public void setProjectId(UUID projectId) { this.projectId = projectId; }
    public void setStatus(AuditStatus status) { this.status = status; }
    public void setProgress(int progress) { this.progress = progress; }
    public void setCurrentStage(String currentStage) { this.currentStage = currentStage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }
    public void setVersion(long version) { this.version = version; }
}
