package com.deepaudit.semantic;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

// 保存 SemanticAnalysisProperties 对应的配置参数。
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "deepaudit.semantic")
public class SemanticAnalysisProperties {
    private boolean enabled = true;
    private int maxCallDepth = 10;
    private int maxPathsPerEntry = 20;
    private int maxStatesPerEntry = 1000;

}
