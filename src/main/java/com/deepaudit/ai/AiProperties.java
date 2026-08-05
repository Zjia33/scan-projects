package com.deepaudit.ai;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "deepaudit.ai")
public class AiProperties {
    private String baseUrl = "https://api.deepseek.com";
    private String apiKey = "";
    private String model = "deepseek-v4-flash";
    private int connectTimeoutSeconds = 10;
    private int readTimeoutSeconds = 120;
    private int jsonRepairAttempts = 2;
    private int maxIterationsPerAgent = 6;
    private int maxToolCallsPerAgent = 10;
    private int maxDetailedObservations = 2;
    private int maxObservationChars = 4_000;
    private int professionalAgentParallelism = 4;
    private int professionalAgentQueueCapacity = 1_000;
    private int triageBatchSize = 20;

}
