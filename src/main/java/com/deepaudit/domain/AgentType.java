package com.deepaudit.domain;

import com.fasterxml.jackson.annotation.JsonCreator;

// 定义 AgentType 使用的固定状态或类型。
public enum AgentType {
    RECON,
    ORCHESTRATOR,
    SQL_INJECTION,
    AUTHORIZATION,
    STORED_XSS,
    VALIDATION_BYPASS,
    FINANCIAL_RISK, // 仅用于读取历史 Agent 轨迹，不再创建新任务
    CRITIC,
    REPORT;

    // 执行 AgentType 中的 fromModelValue 处理。
    @JsonCreator
    public static AgentType fromModelValue(String value) {
        String normalized = ModelEnumNormalizer.normalize(value);
        return switch (normalized) {
            case "SQLI", "SQL_INJECTION_AGENT" -> SQL_INJECTION;
            case "AUTH", "AUTHORIZATION_AGENT", "ACCESS_CONTROL", "UNAUTHORIZED_ACCESS" -> AUTHORIZATION;
            case "XSS", "STORED_XSS_AGENT" -> STORED_XSS;
            case "VALIDATION", "VALIDATION_BYPASS_AGENT", "AUTH_BYPASS" -> VALIDATION_BYPASS;
            case "FINANCIAL", "FINANCIAL_RISK_AGENT", "BUSINESS_LOGIC" -> FINANCIAL_RISK;
            default -> exactOrNull(normalized);
        };
    }

    // 执行 AgentType 中的 exactOrNull 处理。
    private static AgentType exactOrNull(String value) {
        try {
            return value.isBlank() ? null : valueOf(value);
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
