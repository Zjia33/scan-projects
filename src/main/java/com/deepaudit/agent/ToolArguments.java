package com.deepaudit.agent;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;

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

    List<String> strings(String name) {
        Object value = values.get(name.toLowerCase(Locale.ROOT));
        if (value == null) return List.of();
        List<String> result = new ArrayList<>();
        if (value instanceof Iterable<?> iterable) {
            for (Object item : iterable) addString(result, item);
        } else {
            for (String item : String.valueOf(value).split(",")) addString(result, item);
        }
        return List.copyOf(result);
    }

    private void addString(List<String> result, Object value) {
        if (value == null) return;
        String item = String.valueOf(value).strip();
        if (!item.isBlank() && !result.contains(item)) result.add(item);
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

}
