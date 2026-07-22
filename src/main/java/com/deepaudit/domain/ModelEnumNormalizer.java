package com.deepaudit.domain;

import java.util.Locale;

final class ModelEnumNormalizer {
    private ModelEnumNormalizer() {
    }

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
