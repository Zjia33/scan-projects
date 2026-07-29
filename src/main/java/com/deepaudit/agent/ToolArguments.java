package com.deepaudit.agent;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

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
        return value == null ? "" : String.valueOf(value).strip();
    }

    int integer(String name, int defaultValue, int minimum, int maximum) {
        Object value = values.get(name.toLowerCase(Locale.ROOT));
        int parsed = defaultValue;
        if (value instanceof Number number) {
            parsed = number.intValue();
        } else if (value != null) {
            try {
                parsed = Integer.parseInt(String.valueOf(value));
            } catch (NumberFormatException ignored) {
                parsed = defaultValue;
            }
        }
        return Math.max(minimum, Math.min(parsed, maximum));
    }

    Long longValue(String name) {
        Object value = values.get(name.toLowerCase(Locale.ROOT));
        if (value instanceof Number number) return number.longValue();
        if (value == null) return null;
        try {
            return Long.parseLong(String.valueOf(value).replaceAll("[^0-9]", ""));
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    boolean bool(String name, boolean defaultValue) {
        Object value = values.get(name.toLowerCase(Locale.ROOT));
        return value == null ? defaultValue : Boolean.parseBoolean(String.valueOf(value));
    }

}
