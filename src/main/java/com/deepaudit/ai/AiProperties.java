package com.deepaudit.ai;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

// 保存 AiProperties 对应的配置参数。
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "deepaudit.ai")
public class AiProperties {
    private boolean required = true;
    private String baseUrl = "http://localhost:11434/v1";
    private String apiKey = "sk-local-debug-placeholder";
    private String model = "qwen2.5-coder:14b";
    private int connectTimeoutSeconds = 10;
    private int readTimeoutSeconds = 120;
    private int jsonRepairAttempts = 2;
    private int maxIterationsPerAgent = 6;
    private int maxToolCallsPerAgent = 10;
    private int maxDetailedObservations = 2;
    private int maxObservationChars = 4_000;
    private int professionalAgentParallelism = 4;
    private int professionalAgentQueueCapacity = 1_000;
    private int triageBatchSize = 40;

}
