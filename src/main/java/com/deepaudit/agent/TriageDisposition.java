package com.deepaudit.agent;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.Locale;

// 轻量分诊只负责路由：可疑变更进入专业调查，明确无安全意义才跳过。
public enum TriageDisposition {
    INVESTIGATE,
    SKIP;

    @JsonCreator
    public static TriageDisposition fromModelValue(String value) {
        if (value == null || value.isBlank()) return null;
        String normalized = value.strip().replace('-', '_').replace(' ', '_')
                .toUpperCase(Locale.ROOT);
        try {
            return valueOf(normalized);
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
