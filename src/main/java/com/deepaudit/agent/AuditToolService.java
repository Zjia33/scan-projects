package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

// 负责 AuditToolService 对应的业务编排和处理。
@Service
public class AuditToolService {
    private final SemanticEvidenceService semanticEvidenceService;
    private final CodeGraphIntegrationService codeGraphIntegrationService;
    private final ProfessionalToolService professionalToolService;

    // 创建 AuditToolService 实例并初始化所需依赖或状态。
    @Autowired
    public AuditToolService(SemanticEvidenceService semanticEvidenceService,
                            CodeGraphIntegrationService codeGraphIntegrationService,
                            ProfessionalToolService professionalToolService) {
        this.semanticEvidenceService = semanticEvidenceService;
        this.codeGraphIntegrationService = codeGraphIntegrationService;
        this.professionalToolService = professionalToolService;
    }

    // 创建 AuditToolService 实例并初始化所需依赖或状态。
    AuditToolService(SemanticEvidenceService semanticEvidenceService) {
        this(semanticEvidenceService, null, null);
    }

    // 创建 AuditToolService 实例并初始化所需依赖或状态。
    AuditToolService(SemanticEvidenceService semanticEvidenceService,
                     CodeGraphIntegrationService codeGraphIntegrationService) {
        this(semanticEvidenceService, codeGraphIntegrationService, null);
    }

    // 在只读白名单内分发 Agent 工具，并统一限制每次返回的结果数量。
    public ToolResult execute(String tool, Map<String, Object> rawArguments,
                              CodeChunk current, List<CodeChunk> chunks,
                              VulnerabilityType vulnerabilityType) {
        ToolArguments arguments = ToolArguments.of(rawArguments);
        int limit = arguments.integer("limit", 6, 1, 10);
        String normalizedTool = tool == null ? "call_context" : tool.toLowerCase(Locale.ROOT);
        return switch (normalizedTool) {
            case "get_chunk" -> getChunk(reference(arguments, "chunkId"), current, chunks);
            case "verify_relation" -> verifyRelation(reference(arguments, "candidateChunkId"),
                    current, chunks);
            case "call_context" -> addCodeGraphCandidates(callContext(current, chunks, limit),
                    current, chunks, limit);
            case "get_call_chain" -> addCodeGraphCandidates(
                    semantic(normalizedTool, current, limit, vulnerabilityType), current, chunks, limit);
            case "trace_data_flow", "find_security_guards" ->
                    semantic(normalizedTool, current, limit, vulnerabilityType);
            case "search_symbols" -> advanced(professionalToolService == null ? null
                    : professionalToolService.searchSymbols(current.getTaskId(), current, chunks, arguments, limit));
            case "explore_call_graph" -> addCodeGraphCandidates(advanced(professionalToolService == null ? null
                    : professionalToolService.exploreCallGraph(current.getTaskId(), current, chunks,
                    arguments, limit)), current, chunks, limit);
            case "get_change_context" -> advanced(professionalToolService == null ? null
                    : professionalToolService.getChangeContext(current.getTaskId(), current, chunks,
                    arguments, limit));
            case "resolve_data_access" -> advanced(professionalToolService == null ? null
                    : professionalToolService.resolveDataAccess(current.getTaskId(), current, chunks,
                    arguments, limit));
            case "inspect_security_policy" -> advanced(professionalToolService == null ? null
                    : professionalToolService.inspectSecurityPolicy(current.getTaskId(), current, chunks,
                    arguments, limit));
            case "trace_value" -> advanced(professionalToolService == null ? null
                    : professionalToolService.traceValue(current.getTaskId(), current, chunks,
                    arguments, limit, vulnerabilityType));
            default -> throw new IllegalArgumentException("不允许的 Agent 工具: " + tool);
        };
    }

    // 执行 AuditToolService 中的 advanced 处理。
    private ToolResult advanced(ProfessionalToolService.Result result) {
        if (result == null) {
            return new ToolResult("[TOOL_UNAVAILABLE] 当前运行环境未装配高级专业工具。", Set.of(), Set.of());
        }
        return new ToolResult(result.text(), result.evidenceChunkIds(), result.candidateChunkIds());
    }

    // 执行 AuditToolService 中的 reference 处理。
    private String reference(ToolArguments arguments, String name) {
        Long value = arguments.longValue(name);
        return value == null ? null : String.valueOf(value);
    }

    // CodeGraph 关系只作为候选上下文返回，不能绕过 verify_relation 进入允许证据集合。
    private ToolResult addCodeGraphCandidates(ToolResult base, CodeChunk current,
                                              List<CodeChunk> chunks, int limit) {
        if (codeGraphIntegrationService == null) return base;
        CodeGraphIntegrationService.CandidateContext context = codeGraphIntegrationService.candidateContext(
                current.getTaskId(), current, chunks, limit);
        if (context.candidateChunkIds().isEmpty()) return base;
        Set<Long> candidates = new LinkedHashSet<>(base.candidateChunkIds());
        candidates.addAll(context.candidateChunkIds());
        candidates.removeAll(base.evidenceChunkIds());
        String text = base.text() + "\n\n" + context.text();
        return new ToolResult(text, base.evidenceChunkIds(), candidates);
    }

    // 查询已持久化的确定性语义路径并标记其中可直接引用的证据块。
    private ToolResult semantic(String tool, CodeChunk current, int limit, VulnerabilityType vulnerabilityType) {
        SemanticEvidenceService.EvidenceResult result = semanticEvidenceService.query(
                current.getTaskId(), current.getId(), tool, limit, vulnerabilityType);
        return new ToolResult("[SEMANTIC_EVIDENCE]\n" + result.text(), result.evidenceChunkIds());
    }

    // 从同文件和精确调用符号中提取当前目标的直接上下文。
    private ToolResult callContext(CodeChunk current, List<CodeChunk> chunks, int limit) {
        Set<String> called = splitSymbols(current.getCalledSymbols());
        String currentMethod = methodName(current.getSymbolName());
        List<CodeChunk> results = chunks.stream().filter(chunk -> !chunk.getId().equals(current.getId()))
                .filter(chunk -> current.getFilePath().equals(chunk.getFilePath())
                        || called.contains(methodName(chunk.getSymbolName()))
                        || splitSymbols(chunk.getCalledSymbols()).contains(currentMethod))
                .sorted(Comparator.comparing((CodeChunk chunk) -> !hasDirectCallRelation(
                                chunk, called, currentMethod))
                        .thenComparing(chunk -> !current.getFilePath().equals(chunk.getFilePath()))
                        .thenComparing(CodeChunk::getStartLine))
                .limit(limit).toList();
        Set<Long> evidence = results.stream().filter(chunk -> hasDirectCallRelation(chunk, called, currentMethod))
                .map(CodeChunk::getId).collect(Collectors.toCollection(LinkedHashSet::new));
        Set<Long> candidates = results.stream().map(CodeChunk::getId).filter(id -> !evidence.contains(id))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        String text = results.stream().map(chunk -> {
            boolean verified = hasDirectCallRelation(chunk, called, currentMethod);
            return (verified ? "[VERIFIED_EVIDENCE] " : "[UNVERIFIED_CANDIDATE] ")
                    + format(chunk, verified ? "直接调用符号关系" : "仅同文件上下文");
        }).collect(Collectors.joining("\n\n"));
        return new ToolResult(text, evidence, candidates);
    }

    // 判断是否满足 hasDirectCallRelation 对应的条件。
    private boolean hasDirectCallRelation(CodeChunk chunk, Set<String> called, String currentMethod) {
        return called.contains(methodName(chunk.getSymbolName()))
                || splitSymbols(chunk.getCalledSymbols()).contains(currentMethod);
    }

    // 按 ID 读取源码块，但只有当前目标可立即进入允许证据集合。
    private ToolResult getChunk(String chunkReference, CodeChunk current, List<CodeChunk> chunks) {
        Long id = current.getId();
        try {
            if (chunkReference != null && !chunkReference.isBlank()) {
                id = Long.parseLong(chunkReference.replaceAll("[^0-9]", ""));
            }
        } catch (Exception ignored) {
            // 无法解析时读取当前块。
        }
        Long selectedId = id;
        CodeChunk result = chunks.stream().filter(chunk -> selectedId.equals(chunk.getId())).findFirst().orElse(current);
        if (result.getId().equals(current.getId())) {
            return new ToolResult(format(result, "当前审计目标"), Set.of(result.getId()));
        }
        return new ToolResult("[UNVERIFIED_CANDIDATE] 读取候选源码不等于证明关系。\n"
                + format(result, "按ID读取候选"), Set.of(), Set.of(result.getId()));
    }

    // 通过语义图或确定性结构关系把候选提升为已验证证据。
    private ToolResult verifyRelation(String candidateReference, CodeChunk current, List<CodeChunk> chunks) {
        Long candidateId = parseChunkId(candidateReference);
        if (candidateId == null) {
            return new ToolResult("verify_relation 需要提供候选 CHUNK_ID", Set.of(), Set.of());
        }
        CodeChunk candidate = chunks.stream().filter(chunk -> candidateId.equals(chunk.getId())).findFirst().orElse(null);
        if (candidate == null) {
            return new ToolResult("候选代码块不存在: " + candidateId, Set.of(), Set.of());
        }
        SemanticEvidenceService.RelationVerification semantic = semanticEvidenceService.verifyRelation(
                current.getTaskId(), current.getId(), candidateId);
        String structuralReason = structuralRelation(current, candidate);
        boolean verified = semantic.verified() || structuralReason != null;
        String reason = semantic.verified() ? semantic.reason()
                : structuralReason == null ? semantic.reason() : structuralReason;
        if (!verified) {
            return new ToolResult("[RELATION_REJECTED] " + reason + "。该候选不能作为漏洞证据。",
                    Set.of(), Set.of(candidateId));
        }
        return new ToolResult("[VERIFIED_EVIDENCE] " + reason + "\n"
                + format(candidate, "确定性关系验证通过"), Set.of(candidateId), Set.of());
    }

    // 检查精确调用、同一路由或安全策略匹配等无需模型判断的关系。
    private String structuralRelation(CodeChunk current, CodeChunk candidate) {
        String currentMethod = methodName(current.getSymbolName());
        String candidateMethod = methodName(candidate.getSymbolName());
        Set<String> currentCalls = splitSymbols(current.getCalledSymbols());
        Set<String> candidateCalls = splitSymbols(candidate.getCalledSymbols());
        if ((!candidateMethod.isBlank() && currentCalls.contains(candidateMethod))
                || (!currentMethod.isBlank() && candidateCalls.contains(currentMethod))) {
            return "代码块之间存在精确方法调用符号关系";
        }
        if (current.getEndpoint() != null && current.getEndpoint().equals(candidate.getEndpoint())) {
            return "代码块属于同一个接口路由";
        }
        if (securityPolicyMatches(current.getEndpoint(), candidate.getContent())) {
            return "候选安全配置能够匹配当前接口路径";
        }
        return null;
    }

    // 执行 AuditToolService 中的 securityPolicyMatches 处理。
    private boolean securityPolicyMatches(String endpoint, String content) {
        if (endpoint == null || content == null) return false;
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(
                "requestMatchers\\s*\\(([^)]*)\\)", java.util.regex.Pattern.CASE_INSENSITIVE).matcher(content);
        while (matcher.find()) {
            java.util.regex.Matcher quoted = java.util.regex.Pattern.compile("[\\\"']([^\\\"']+)[\\\"']")
                    .matcher(matcher.group(1));
            while (quoted.find()) {
                if (endpointMatches(endpoint, quoted.group(1))) return true;
            }
        }
        return false;
    }

    // 执行 AuditToolService 中的 endpointMatches 处理。
    private boolean endpointMatches(String endpoint, String antPattern) {
        StringBuilder regex = new StringBuilder("^");
        for (int index = 0; index < antPattern.length(); index++) {
            char current = antPattern.charAt(index);
            if (current == '*' && index + 1 < antPattern.length() && antPattern.charAt(index + 1) == '*') {
                regex.append(".*");
                index++;
            } else if (current == '*') {
                regex.append("[^/]*");
            } else if (current == '{') {
                int end = antPattern.indexOf('}', index + 1);
                if (end > index) {
                    regex.append("[^/]+");
                    index = end;
                } else {
                    regex.append(java.util.regex.Pattern.quote(String.valueOf(current)));
                }
            } else {
                regex.append(java.util.regex.Pattern.quote(String.valueOf(current)));
            }
        }
        return endpoint.matches(regex.append('$').toString());
    }

    // 解析输入并生成 parseChunkId 对应的结构化结果。
    private Long parseChunkId(String chunkReference) {
        if (chunkReference == null) return null;
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("\\d+").matcher(chunkReference);
        if (!matcher.find()) return null;
        try { return Long.parseLong(matcher.group()); } catch (NumberFormatException exception) { return null; }
    }

    // 将源码包裹为不可信代码片段，避免其文本被当作 Agent 指令执行。
    private String format(CodeChunk chunk, String reason) {
        String code = chunk.getContent().substring(0, Math.min(chunk.getContent().length(), 4_000));
        return "CHUNK_ID=" + chunk.getId() + " | " + chunk.getFilePath() + ":" + chunk.getStartLine()
                + " | " + chunk.getSymbolName() + " | reason=" + reason
                + "\n<UNTRUSTED_CODE>\n" + code
                + "\n</UNTRUSTED_CODE>";
    }

    // 执行 AuditToolService 中的 ids 处理。
    private Set<Long> ids(List<CodeChunk> chunks) {
        return chunks.stream().map(CodeChunk::getId).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    // 执行 AuditToolService 中的 splitSymbols 处理。
    private Set<String> splitSymbols(String value) {
        if (value == null || value.isBlank()) return Set.of();
        return Arrays.stream(value.split(",")).map(String::strip).filter(item -> !item.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    // 执行 AuditToolService 中的 methodName 处理。
    private String methodName(String symbol) {
        if (symbol == null) return "";
        int hash = symbol.lastIndexOf('#');
        return hash < 0 ? symbol : symbol.substring(hash + 1);
    }

    // 封装 ToolResult 使用的不可变结构化数据。
    public record ToolResult(String text, Set<Long> evidenceChunkIds, Set<Long> candidateChunkIds) {
        // 创建 ToolResult 实例并初始化所需依赖或状态。
        public ToolResult(String text, Set<Long> evidenceChunkIds) {
            this(text, evidenceChunkIds, Set.of());
        }

        // 校验并规范化 ToolResult 的构造参数。
        public ToolResult {
            text = text == null || text.isBlank() ? "未检索到相关代码" : text;
            evidenceChunkIds = evidenceChunkIds == null ? Set.of() : Set.copyOf(evidenceChunkIds);
            candidateChunkIds = candidateChunkIds == null ? Set.of() : Set.copyOf(candidateChunkIds);
        }
    }
}
