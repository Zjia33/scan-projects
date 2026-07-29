package com.deepaudit.analysis;

import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;

import java.util.UUID;

// 封装 FindingDraft 使用的不可变结构化数据。
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
    // 转换并返回 toEntity 对应的数据表示。
    public Finding toEntity(UUID taskId) {
        return new Finding(taskId, type, severity, confidence, title, filePath, startLine, endLine,
                endpoint, description, evidence, remediation);
    }
}
