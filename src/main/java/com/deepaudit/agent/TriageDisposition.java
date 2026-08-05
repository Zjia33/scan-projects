package com.deepaudit.agent;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.Locale;

// 表示轻量编排阶段对审计单元的三态处理决定。
public enum TriageDisposition {
    INVESTIGATE,
    NEED_CONTEXT,
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
