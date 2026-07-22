package com.deepaudit.domain;

import java.time.Instant;
import java.util.UUID;

public class Finding {

    private UUID id;
    private UUID taskId;
    private VulnerabilityType type;
    private Severity severity;
    private Confidence confidence;
    private String title;
    private String filePath;
    private int startLine;
    private int endLine;
    private String endpoint;
    private String description;
    private String evidence;
    private String remediation;
    private Instant createdAt;

    public Finding() {
    }

    public Finding(UUID taskId, VulnerabilityType type, Severity severity, Confidence confidence,
                   String title, String filePath, int startLine, int endLine, String endpoint,
                   String description, String evidence, String remediation) {
        this.id = UUID.randomUUID();
        this.taskId = taskId;
        this.type = type;
        this.severity = severity;
        this.confidence = confidence;
        this.title = title;
        this.filePath = filePath;
        this.startLine = startLine;
        this.endLine = endLine;
        this.endpoint = endpoint;
        this.description = description;
        this.evidence = evidence;
        this.remediation = remediation;
        this.createdAt = Instant.now();
    }

    public UUID getId() { return id; }
    public UUID getTaskId() { return taskId; }
    public VulnerabilityType getType() { return type; }
    public Severity getSeverity() { return severity; }
    public Confidence getConfidence() { return confidence; }
    public String getTitle() { return title; }
    public String getFilePath() { return filePath; }
    public int getStartLine() { return startLine; }
    public int getEndLine() { return endLine; }
    public String getEndpoint() { return endpoint; }
    public String getDescription() { return description; }
    public String getEvidence() { return evidence; }
    public String getRemediation() { return remediation; }
    public Instant getCreatedAt() { return createdAt; }
    public void setId(UUID id) { this.id = id; }
    public void setTaskId(UUID taskId) { this.taskId = taskId; }
    public void setType(VulnerabilityType type) { this.type = type; }
    public void setSeverity(Severity severity) { this.severity = severity; }
    public void setConfidence(Confidence confidence) { this.confidence = confidence; }
    public void setTitle(String title) { this.title = title; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    public void setStartLine(int startLine) { this.startLine = startLine; }
    public void setEndLine(int endLine) { this.endLine = endLine; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
    public void setDescription(String description) { this.description = description; }
    public void setEvidence(String evidence) { this.evidence = evidence; }
    public void setRemediation(String remediation) { this.remediation = remediation; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
