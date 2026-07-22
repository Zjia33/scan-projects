package com.deepaudit.domain;

import java.time.Instant;
import java.util.UUID;

public class AiReportSummary {
    private UUID taskId;
    private String executiveSummary;
    private String coverageSummary;
    private Instant generatedAt;

    public AiReportSummary() {
    }

    public AiReportSummary(UUID taskId, String executiveSummary, String coverageSummary) {
        this.taskId = taskId;
        this.executiveSummary = executiveSummary;
        this.coverageSummary = coverageSummary;
        this.generatedAt = Instant.now();
    }

    public UUID getTaskId() { return taskId; }
    public String getExecutiveSummary() { return executiveSummary; }
    public String getCoverageSummary() { return coverageSummary; }
    public Instant getGeneratedAt() { return generatedAt; }
    public void setTaskId(UUID taskId) { this.taskId = taskId; }
    public void setExecutiveSummary(String executiveSummary) { this.executiveSummary = executiveSummary; }
    public void setCoverageSummary(String coverageSummary) { this.coverageSummary = coverageSummary; }
    public void setGeneratedAt(Instant generatedAt) { this.generatedAt = generatedAt; }
}
