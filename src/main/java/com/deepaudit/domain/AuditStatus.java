package com.deepaudit.domain;

// 定义 AuditStatus 使用的固定状态或类型。
public enum AuditStatus {
    UPLOADED,
    MATERIALIZING,
    DIFFING,
    INVENTORY,
    INDEXING,
    RECON,
    AGENT_RECON,
    PLANNING,
    ANALYSIS,
    CRITIC_REVIEW,
    RESULT_VALIDATION,
    REPORTING,
    COMPLETED,
    FAILED,
    CANCELLED
}
