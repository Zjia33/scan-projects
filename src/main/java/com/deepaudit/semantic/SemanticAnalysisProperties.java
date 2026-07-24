package com.deepaudit.semantic;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

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
