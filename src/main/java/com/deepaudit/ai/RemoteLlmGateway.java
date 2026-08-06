package com.deepaudit.ai;

import com.deepaudit.agent.IncrementalReviewUnit;
import com.deepaudit.recon.ReconSummary;
import com.deepaudit.util.ExecutionTiming;
import com.deepaudit.util.TimingDetailLog;
import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
@Service
public class RemoteLlmGateway implements LlmGateway {
    private final AiProperties properties;
    private final ObjectMapper objectMapper;
    private final ObjectMapper tolerantObjectMapper;
    private final RestClient restClient;

    public RemoteLlmGateway(AiProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.tolerantObjectMapper = objectMapper.copy()
                .enable(JsonReadFeature.ALLOW_TRAILING_COMMA.mappedFeature())
                .enable(JsonReadFeature.ALLOW_UNESCAPED_CONTROL_CHARS.mappedFeature())
                .enable(JsonReadFeature.ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER.mappedFeature())
                .enable(JsonParser.Feature.ALLOW_SINGLE_QUOTES)
                .enable(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES);
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(properties.getConnectTimeoutSeconds())).build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(client);
        factory.setReadTimeout(Duration.ofSeconds(properties.getReadTimeoutSeconds()));
        this.restClient = RestClient.builder().baseUrl(properties.getBaseUrl()).requestFactory(factory).build();
    }

    // 请求 Recon 模型只根据构建描述、应用配置和去计数后的框架事实生成架构摘要。
    @Override
    public ReconInsight inspectProject(UUID taskId, ReconSummary summary) {
        String systemPrompt = AgentPrompts.reconAgent();
        String userPrompt = json(Map.of("projectFramework", summary.frameworkFacts(),
                "outputSchema", Map.of("architectureSummary",
                        "仅包含整体技术框架、模块、分层和基础组件事实的 string")));
        return call(taskId, "RECON", systemPrompt, userPrompt, ReconInsight.class);
    }

    // 增量分流读取真实 Base/Target 摘录，不使用 Recon 模型摘要或预猜测的候选漏洞类型。
    @Override
    public TriagePlan triageIncremental(UUID taskId, ReconInsight recon,
                                        List<IncrementalReviewUnit> reviewUnits) {
        String systemPrompt = AgentPrompts.incrementalTriage();
        String userPrompt = json(Map.of("taskId", taskId,
                "projectTechnology", recon.technologyProfile(), "reviewUnits", reviewUnits,
                "outputSchema", Map.of("summary", "string", "decisions",
                        "[{unitId,primaryChunkId,disposition:INVESTIGATE|SKIP,"
                                + "vulnerabilityTypes:[],reason,"
                                + "focusRanges:[{startLine,endLine}],investigationQuestions:[]}]")));
        return call(taskId, "TRIAGE_CHANGED", systemPrompt, userPrompt, TriagePlan.class);
    }

    // 请求专业 Agent 在 TOOL、FINDING 和 REJECT 三类受控动作中选择下一步。
    @Override
    public AgentDecision decide(AgentTurn turn) {
        String systemPrompt = AgentPrompts.professionalAgent(turn.vulnerabilityType());
        String userPrompt = json(Map.of("turn", turn, "outputSchema", Map.of(
                "action", "TOOL|FINDING|REJECT", "tool", "string|null",
                "arguments", "object，按工具定义提供结构化参数，limit放在此对象内",
                "summary", "string", "finding",
                "null|{type:输入中的漏洞枚举,severity:CRITICAL|HIGH|MEDIUM|LOW,"
                        + "confidence:HIGH|MEDIUM|LOW,title,description,remediation,"
                        + "primaryChunkId,evidenceChunkIds,vulnerabilityStartLine,vulnerabilityEndLine}")));
        return call(turn.taskId(), "PROFESSIONAL:" + turn.agentType() + ":" + turn.iteration(),
                systemPrompt, userPrompt, AgentDecision.class);
    }

    // 请求 Report Agent 只改写已确认事实，不允许在报告阶段新增漏洞。
    @Override
    public ReportNarrative writeReport(ReportRequest request) {
        String systemPrompt = AgentPrompts.reportAgent();
        String userPrompt = json(Map.of("reportFacts", request, "outputSchema",
                Map.of("executiveSummary", "string", "coverageSummary", "string")));
        return call(request.taskId(), "REPORT", systemPrompt, userPrompt, ReportNarrative.class);
    }

    // 统一执行模型调用、结构化解析和有限次数的 JSON 纠正重试。
    private <T> T call(UUID taskId, String operation, String system, String user, Class<T> responseType) {
        return call(taskId, operation, system, user, responseType, ignored -> null);
    }

    private <T> T call(UUID taskId, String operation, String system, String user, Class<T> responseType,
                       Function<T, String> responseValidator) {
        List<Map<String, String>> messages = new ArrayList<>();
        messages.add(Map.of("role", "system", "content", system));
        messages.add(Map.of("role", "user", "content", user));
        int repairAttempts = Math.max(0, Math.min(properties.getJsonRepairAttempts(), 3));
        JsonProcessingException lastParsingException = null;
        long logicalStarted = ExecutionTiming.start();

        // 解析失败时把错误位置反馈给模型重建更短 JSON，而不静默接受错误结构。
        for (int attempt = 0; attempt <= repairAttempts; attempt++) {
            int requestNumber = attempt + 1;
            int inputChars = messages.stream().mapToInt(message -> message.getOrDefault("content", "").length()).sum();
            long requestStarted = ExecutionTiming.start();
            TimingDetailLog.info("模型请求开始：taskId={}，operation={}，type={}，request={}/{}，messages={}，inputChars={}",
                    taskId, operation, responseType.getSimpleName(), requestNumber,
                    repairAttempts + 1, messages.size(), inputChars);
            String content;
            try {
                content = requestCompletion(messages);
            } catch (Exception exception) {
                log.error("模型请求失败：taskId={}，operation={}，type={}，request={}/{}，elapsedMs={}，inputChars={}，error={}",
                        taskId, operation, responseType.getSimpleName(), requestNumber,
                        repairAttempts + 1, ExecutionTiming.elapsedMillis(requestStarted), inputChars,
                        exception.getClass().getSimpleName());
                throw new AiUnavailableException("必需的大模型调用失败: " + exception.getMessage(), exception);
            }
            long requestElapsedMs = ExecutionTiming.elapsedMillis(requestStarted);
            int outputChars = content == null ? 0 : content.length();
            TimingDetailLog.info("模型响应完成：taskId={}，operation={}，type={}，request={}/{}，elapsedMs={}，inputChars={}，outputChars={}",
                    taskId, operation, responseType.getSimpleName(), requestNumber,
                    repairAttempts + 1, requestElapsedMs, inputChars, outputChars);
            try {
                T parsed = parseResponse(content, responseType);
                String validationError = responseValidator.apply(parsed);
                if (validationError != null && !validationError.isBlank()) {
                    throw new com.fasterxml.jackson.core.JsonParseException((JsonParser) null,
                            validationError);
                }
                TimingDetailLog.info("模型调用完成：taskId={}，operation={}，type={}，requests={}，totalElapsedMs={}，outputChars={}",
                        taskId, operation, responseType.getSimpleName(), requestNumber,
                        ExecutionTiming.elapsedMillis(logicalStarted), outputChars);
                return parsed;
            } catch (JsonProcessingException exception) {
                lastParsingException = exception;
                if (attempt >= repairAttempts) break;
                TimingDetailLog.warn("模型结构化响应无效，准备纠正：taskId={}，operation={}，request={}/{}，type={}，totalElapsedMs={}，原因={}，错误位置={}",
                        taskId, operation, requestNumber, repairAttempts + 1, responseType.getSimpleName(),
                        ExecutionTiming.elapsedMillis(logicalStarted),
                        safeValidationMessage(exception), formatLocation(exception));
                messages.add(Map.of("role", "assistant", "content", content));
                messages.add(Map.of("role", "user", "content",
                        AgentPrompts.jsonRepair(safeValidationMessage(exception)
                                + "；" + formatLocation(exception))));
            }
        }
        log.warn("模型调用结构校验失败：taskId={}，operation={}，type={}，requests={}，totalElapsedMs={}",
                taskId, operation, responseType.getSimpleName(), repairAttempts + 1,
                ExecutionTiming.elapsedMillis(logicalStarted));
        throw new AiResponseFormatException("必需的大模型调用失败: 模型在 " + (repairAttempts + 1)
                + " 次响应后仍未返回合法结构化结果，最后错误位置: " + formatLocation(lastParsingException),
                lastParsingException);
    }

    private String safeValidationMessage(JsonProcessingException exception) {
        if (exception == null || exception.getOriginalMessage() == null) return "未知结构错误";
        String message = exception.getOriginalMessage().replaceAll("[\\r\\n\\t]", " ").strip();
        return message.substring(0, Math.min(message.length(), 240));
    }

    // 发送 OpenAI-compatible Chat Completions 请求，独立成方法便于无网络测试替换。
    protected String requestCompletion(List<Map<String, String>> messages) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", properties.getModel());
        body.put("temperature", 0);
        body.put("response_format", Map.of("type", "json_object"));
        body.put("messages", messages);
        RestClient.RequestBodySpec request = restClient.post().uri("/chat/completions")
                .contentType(MediaType.APPLICATION_JSON);
        if (properties.getApiKey() != null && !properties.getApiKey().isBlank()) {
            request.header("Authorization", "Bearer " + properties.getApiKey());
        }
        JsonNode response = request.body(body).retrieve().body(JsonNode.class);
        return response == null ? "" : response.path("choices").path(0)
                .path("message").path("content").asText();
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalStateException("无法构造 Agent 请求", exception);
        }
    }

    // 去除常见 Markdown 包装和对象外文本后再进入 JSON 解析。
    private String normalizeJsonResponse(String value) {
        String result = value == null ? "" : value.strip();
        if (result.startsWith("```")) {
            result = result.replaceFirst("^```(?:json)?\\s*", "").replaceFirst("\\s*```$", "");
        }
        int objectStart = result.indexOf('{');
        int objectEnd = result.lastIndexOf('}');
        if (objectStart > 0 && objectEnd > objectStart) {
            result = result.substring(objectStart, objectEnd + 1);
        }
        return result;
    }

    // 依次尝试严格、宽容和本地安全修复解析，仍失败则触发模型纠正。
    private <T> T parseResponse(String content, Class<T> responseType) throws JsonProcessingException {
        String normalized = normalizeJsonResponse(content);
        JsonProcessingException strictFailure;
        try {
            return objectMapper.readValue(normalized, responseType);
        } catch (JsonProcessingException exception) {
            strictFailure = exception;
        }
        try {
            return tolerantObjectMapper.readValue(normalized, responseType);
        } catch (JsonProcessingException ignored) {
            // 继续尝试修复模型最常见的未转义引号和控制字符。
        }
        String repaired = repairStringContent(normalized);
        if (!repaired.equals(normalized)) {
            try {
                T result = tolerantObjectMapper.readValue(repaired, responseType);
                TimingDetailLog.info("模型 JSON 已由本地解析器安全修复，无需额外模型调用");
                return result;
            } catch (JsonProcessingException ignored) {
                // 使用原始严格解析错误生成模型重建提示，位置更接近真实响应。
            }
        }
        throw strictFailure;
    }

    // 仅修复 JSON 字符串中的未转义引号和控制字符，不改写字段结构。
    private String repairStringContent(String json) {
        StringBuilder repaired = new StringBuilder(json.length() + 32);
        boolean inString = false;
        boolean escaped = false;
        for (int index = 0; index < json.length(); index++) {
            char current = json.charAt(index);
            if (!inString) {
                repaired.append(current);
                if (current == '"') inString = true;
                continue;
            }
            if (escaped) {
                repaired.append(current);
                escaped = false;
                continue;
            }
            if (current == '\\') {
                repaired.append(current);
                escaped = true;
                continue;
            }
            if (current == '"') {
                if (isClosingQuote(json, index + 1)) {
                    repaired.append(current);
                    inString = false;
                } else {
                    repaired.append("\\\"");
                }
                continue;
            }
            if (current == '\n') {
                repaired.append("\\n");
            } else if (current == '\r') {
                repaired.append("\\r");
            } else if (current == '\t') {
                repaired.append("\\t");
            } else if (current < 0x20) {
                repaired.append(' ');
            } else {
                repaired.append(current);
            }
        }
        return repaired.toString();
    }

    private boolean isClosingQuote(String json, int start) {
        for (int index = start; index < json.length(); index++) {
            char next = json.charAt(index);
            if (Character.isWhitespace(next)) continue;
            return next == ',' || next == '}' || next == ']' || next == ':';
        }
        return true;
    }

    private String formatLocation(JsonProcessingException exception) {
        if (exception == null) return "未知";
        JsonLocation location = exception.getLocation();
        if (location == null) return "未知";
        return "第 " + location.getLineNr() + " 行，第 " + location.getColumnNr() + " 列";
    }

}
