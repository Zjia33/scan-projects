package com.deepaudit.codegraph;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

// 保存 CodeGraphProperties 对应的配置参数。
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "deepaudit.codegraph")
public class CodeGraphProperties {
    private CodeGraphMode mode = CodeGraphMode.OFF;
    private String executable = "codegraph";
    private String bundleRoot = "";
    private String expectedVersion = "";
    private int timeoutSeconds = 120;
    private long maxOutputBytes = 8L * 1024L * 1024L;
    private int impactDepth = 2;
    private int agentContextLimit = 10;
    private String indexDirectory = ".codegraph-deepaudit";

    // 执行 CodeGraphProperties 中的 enabled 处理。
    public boolean enabled() {
        return mode != CodeGraphMode.OFF;
    }

    // 执行 CodeGraphProperties 中的 augmentsResults 处理。
    public boolean augmentsResults() {
        return mode == CodeGraphMode.AUGMENT;
    }
}
