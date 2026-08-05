package com.deepaudit.domain;

import com.fasterxml.jackson.annotation.JsonCreator;

// 定义 AgentType 使用的固定状态或类型。
public enum AgentType {
    RECON,
    ORCHESTRATOR,
    SQL_INJECTION,
    AUTHORIZATION,
    SENSITIVE_INFORMATION,
    STORED_XSS,
    VALIDATION_BYPASS,
    CRITIC,
    REPORT;

    @JsonCreator
    public static AgentType fromModelValue(String value) {
        String normalized = ModelEnumNormalizer.normalize(value);
        return switch (normalized) {
            case "SQLI", "SQL_INJECTION_AGENT" -> SQL_INJECTION;
            case "AUTH", "AUTHORIZATION_AGENT", "ACCESS_CONTROL", "UNAUTHORIZED_ACCESS" -> AUTHORIZATION;
            case "SENSITIVE_INFORMATION_AGENT", "INFORMATION_DISCLOSURE", "DATA_LEAK" -> SENSITIVE_INFORMATION;
            case "XSS", "STORED_XSS_AGENT" -> STORED_XSS;
            case "VALIDATION", "VALIDATION_BYPASS_AGENT", "AUTH_BYPASS" -> VALIDATION_BYPASS;
            default -> exactOrNull(normalized);
        };
    }

    private static AgentType exactOrNull(String value) {
        try {
            return value.isBlank() ? null : valueOf(value);
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
