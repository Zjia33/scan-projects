package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
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
    private FindingDeltaStatus deltaStatus;
    private String fingerprint;
    private Instant createdAt;

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
        this.deltaStatus = FindingDeltaStatus.BASELINE;
        this.createdAt = Instant.now();
    }

}
