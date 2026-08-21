package com.deepaudit.agent;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

final class ToolArguments {
    private final Map<String, Object> values;

    private ToolArguments(Map<String, Object> values) {
        this.values = new LinkedHashMap<>();
        if (values != null) {
            values.forEach((key, value) -> {
                if (key != null && value != null) this.values.put(key.toLowerCase(Locale.ROOT), value);
            });
        }
    }

    static ToolArguments of(Map<String, Object> values) {
        return new ToolArguments(values);
    }

    String string(String name) {
        Object value = values.get(name.toLowerCase(Locale.ROOT));
        if (value == null) return "";
        if (!(value instanceof String text)) throw invalid(name, "必须是 JSON 字符串");
        return text.strip();
    }

    int integer(String name, int defaultValue, int minimum, int maximum) {
        Object value = values.get(name.toLowerCase(Locale.ROOT));
        if (value == null) return defaultValue;
        int parsed = exactInteger(name, value);
        if (parsed < minimum || parsed > maximum) {
            throw invalid(name, "必须位于 " + minimum + ".." + maximum + " 范围内");
        }
        return parsed;
    }

    Long longValue(String name) {
        Object value = values.get(name.toLowerCase(Locale.ROOT));
        if (value == null) return null;
        try {
            if (!(value instanceof Number)) throw invalid(name, "必须是 JSON 整数");
            long parsed = new BigDecimal(value.toString()).longValueExact();
            if (parsed < 0) throw invalid(name, "不能是负数");
            return parsed;
        } catch (ArithmeticException exception) {
            throw invalid(name, "必须是有效的 JSON 整数");
        }
    }

    boolean bool(String name, boolean defaultValue) {
        Object value = values.get(name.toLowerCase(Locale.ROOT));
        if (value == null) return defaultValue;
        if (!(value instanceof Boolean result)) throw invalid(name, "必须是 JSON boolean");
        return result;
    }

    boolean has(String name) {
        return values.containsKey(name.toLowerCase(Locale.ROOT));
    }

    Set<String> unknownKeys(Set<String> allowed) {
        Set<String> normalizedAllowed = new LinkedHashSet<>();
        allowed.forEach(value -> normalizedAllowed.add(value.toLowerCase(Locale.ROOT)));
        return values.keySet().stream()
                .filter(key -> !normalizedAllowed.contains(key))
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
    }

    private int exactInteger(String name, Object value) {
        if (!(value instanceof Number)) throw invalid(name, "必须是 JSON 整数");
        try {
            return new BigDecimal(value.toString()).intValueExact();
        } catch (ArithmeticException exception) {
            throw invalid(name, "必须是有效的 JSON 整数");
        }
    }

    private InvalidArgumentException invalid(String name, String reason) {
        return new InvalidArgumentException("参数 " + name + " " + reason + "。");
    }

    static final class InvalidArgumentException extends IllegalArgumentException {
        private InvalidArgumentException(String message) {
            super(message);
        }
    }

}
