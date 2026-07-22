package com.deepaudit.analysis;

import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;

import java.util.UUID;

public record FindingDraft(
        VulnerabilityType type,
        Severity severity,
        Confidence confidence,
        String title,
        String filePath,
        int startLine,
        int endLine,
        String endpoint,
        String description,
        String evidence,
        String remediation
) {
    public Finding toEntity(UUID taskId) {
        return new Finding(taskId, type, severity, confidence, title, filePath, startLine, endLine,
                endpoint, description, evidence, remediation);
    }
}
