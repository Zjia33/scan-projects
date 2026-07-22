package com.deepaudit.domain;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum AgentType {
    RECON,
    ORCHESTRATOR,
    SQL_INJECTION,
    AUTHORIZATION,
    STORED_XSS,
    VALIDATION_BYPASS,
    FINANCIAL_RISK,
    CRITIC,
    REPORT;

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

    private static AgentType exactOrNull(String value) {
        try {
            return value.isBlank() ? null : valueOf(value);
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
