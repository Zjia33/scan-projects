package com.deepaudit.codegraph;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "deepaudit.codegraph")
public class CodeGraphProperties {
    private boolean enabled = true;
    private String executable = "";
    private String bundleRoot = "";
    private String expectedVersion = "";
    private int timeoutSeconds = 120;
    private long maxOutputBytes = 8L * 1024L * 1024L;
    private int impactDepth = 2;
    private int relationLimit = 100;
    private int agentContextLimit = 10;
    private String indexDirectory = ".codegraph-deepaudit";

}
