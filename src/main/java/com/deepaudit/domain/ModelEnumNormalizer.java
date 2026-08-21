package com.deepaudit.domain;

import java.util.Locale;

// 表示审计领域中的 ModelEnumNormalizer 数据实体。
final class ModelEnumNormalizer {
    private ModelEnumNormalizer() {
    }

    // 规范化 normalize 对应的输入。
    static String normalize(String value) {
        if (value == null || value.isBlank()) return "";
        return value.strip()
                .replaceAll("([a-z0-9])([A-Z])", "$1_$2")
                .replaceAll("[^\\p{L}\\p{N}]+", "_")
                .replaceAll("_+", "_")
                .replaceAll("^_|_$", "")
                .toUpperCase(Locale.ROOT);
    }
}
