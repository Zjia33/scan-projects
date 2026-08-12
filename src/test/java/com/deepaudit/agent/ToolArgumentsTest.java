package com.deepaudit.agent;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ToolArgumentsTest {

    @Test
    void rejectsImplicitConversionsAndOutOfRangeNumbers() {
        assertThatThrownBy(() -> ToolArguments.of(Map.of("limit", "6"))
                .integer("limit", 6, 1, 10))
                .isInstanceOf(ToolArguments.InvalidArgumentException.class)
                .hasMessageContaining("limit", "JSON 整数");
        assertThatThrownBy(() -> ToolArguments.of(Map.of("limit", 11))
                .integer("limit", 6, 1, 10))
                .isInstanceOf(ToolArguments.InvalidArgumentException.class)
                .hasMessageContaining("1..10");
        assertThatThrownBy(() -> ToolArguments.of(Map.of("chunkId", "chunk-12"))
                .longValue("chunkId"))
                .isInstanceOf(ToolArguments.InvalidArgumentException.class)
                .hasMessageContaining("chunkId", "JSON 整数");
        assertThatThrownBy(() -> ToolArguments.of(Map.of("includeTests", "true"))
                .bool("includeTests", false))
                .isInstanceOf(ToolArguments.InvalidArgumentException.class)
                .hasMessageContaining("includeTests", "JSON boolean");
    }
}
