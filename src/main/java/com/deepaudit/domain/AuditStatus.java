package com.deepaudit.domain;

public enum AuditStatus {
    UPLOADED,
    EXTRACTING,
    INVENTORY,
    INDEXING,
    RECON,
    AGENT_RECON,
    PLANNING,
    CANDIDATE_GENERATION,
    ANALYSIS,
    CRITIC_REVIEW,
    RESULT_VALIDATION,
    REPORTING,
    COMPLETED,
    FAILED,
    CANCELLED
}
