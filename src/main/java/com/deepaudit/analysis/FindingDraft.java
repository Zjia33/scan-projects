package com.deepaudit.analysis;

import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;

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
}
