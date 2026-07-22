package com.deepaudit.ai;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

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
    private int professionalAgentParallelism = 4;
    private int plannerBatchSize = 12;
    private int maxAuditTargets = 200;

    public boolean isRequired() { return required; }
    public String getBaseUrl() { return baseUrl; }
    public String getApiKey() { return apiKey; }
    public String getModel() { return model; }
    public int getConnectTimeoutSeconds() { return connectTimeoutSeconds; }
    public int getReadTimeoutSeconds() { return readTimeoutSeconds; }
    public int getJsonRepairAttempts() { return jsonRepairAttempts; }
    public int getMaxIterationsPerAgent() { return maxIterationsPerAgent; }
    public int getMaxToolCallsPerAgent() { return maxToolCallsPerAgent; }
    public int getProfessionalAgentParallelism() { return professionalAgentParallelism; }
    public int getPlannerBatchSize() { return plannerBatchSize; }
    public int getMaxAuditTargets() { return maxAuditTargets; }
    public void setRequired(boolean required) { this.required = required; }
    public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }
    public void setModel(String model) { this.model = model; }
    public void setConnectTimeoutSeconds(int value) { this.connectTimeoutSeconds = value; }
    public void setReadTimeoutSeconds(int value) { this.readTimeoutSeconds = value; }
    public void setJsonRepairAttempts(int value) { this.jsonRepairAttempts = value; }
    public void setMaxIterationsPerAgent(int value) { this.maxIterationsPerAgent = value; }
    public void setMaxToolCallsPerAgent(int value) { this.maxToolCallsPerAgent = value; }
    public void setProfessionalAgentParallelism(int value) { this.professionalAgentParallelism = value; }
    public void setPlannerBatchSize(int value) { this.plannerBatchSize = value; }
    public void setMaxAuditTargets(int value) { this.maxAuditTargets = value; }
}
