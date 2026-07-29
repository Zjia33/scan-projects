package com.deepaudit.agent;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

// 封装 ToolArguments 相关的数据与处理逻辑。
final class ToolArguments {
    private final Map<String, Object> values;

    // 创建 ToolArguments 实例并初始化所需依赖或状态。
    private ToolArguments(Map<String, Object> values) {
        this.values = new LinkedHashMap<>();
        if (values != null) {
            values.forEach((key, value) -> {
                if (key != null && value != null) this.values.put(key.toLowerCase(Locale.ROOT), value);
            });
        }
    }

    // 执行 ToolArguments 中的 of 处理。
    static ToolArguments of(Map<String, Object> values) {
        return new ToolArguments(values);
    }

    // 执行 ToolArguments 中的 string 处理。
    String string(String name) {
        Object value = values.get(name.toLowerCase(Locale.ROOT));
        return value == null ? "" : String.valueOf(value).strip();
    }

    // 执行 ToolArguments 中的 integer 处理。
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

    // 执行 ToolArguments 中的 longValue 处理。
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

    // 执行 ToolArguments 中的 bool 处理。
    boolean bool(String name, boolean defaultValue) {
        Object value = values.get(name.toLowerCase(Locale.ROOT));
        return value == null ? defaultValue : Boolean.parseBoolean(String.valueOf(value));
    }

}
