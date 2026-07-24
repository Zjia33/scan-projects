package com.deepaudit.agent;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.rag.RagService;
import com.deepaudit.semantic.SemanticEvidenceService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuditToolService {
    private final RagService ragService;
    private final SemanticEvidenceService semanticEvidenceService;

    // 在只读白名单内分发 Agent 工具，并统一限制每次返回的结果数量。
    public ToolResult execute(String tool, String query, int requestedLimit,
                              CodeChunk current, List<CodeChunk> chunks,
                              VulnerabilityType vulnerabilityType) {
        int limit = Math.max(1, Math.min(requestedLimit <= 0 ? 6 : requestedLimit, 10));
        String normalizedTool = tool == null ? "hybrid_search" : tool.toLowerCase(Locale.ROOT);
        return switch (normalizedTool) {
            case "get_chunk" -> getChunk(query, current, chunks);
            case "verify_relation" -> verifyRelation(query, current, chunks);
            case "call_context" -> callContext(current, chunks, limit);
            case "get_call_chain", "trace_data_flow", "find_security_guards" ->
                    semantic(normalizedTool, current, limit, vulnerabilityType);
            case "security_controls" -> semanticFirst("find_security_guards", current, chunks,
                    append(query, "authentication authorization currentUser owner tenant role permission guard validate"),
                    limit, vulnerabilityType);
            case "data_access" -> semanticFirst("trace_data_flow", current, chunks,
                    append(query, "SQL mapper repository select insert update delete execute query parameter"),
                    limit, vulnerabilityType);
            case "hybrid_search" -> search(current, chunks, query, limit);
            default -> throw new IllegalArgumentException("不允许的 Agent 工具: " + tool);
        };
    }

    // 查询已持久化的确定性语义路径并标记其中可直接引用的证据块。
    private ToolResult semantic(String tool, CodeChunk current, int limit, VulnerabilityType vulnerabilityType) {
        SemanticEvidenceService.EvidenceResult result = semanticEvidenceService.query(
                current.getTaskId(), current.getId(), tool, limit, vulnerabilityType);
        return new ToolResult("[SEMANTIC_EVIDENCE]\n" + result.text(), result.evidenceChunkIds());
    }

    // 在语义证据缺失时合并 RAG 候选，同时保留两类结果的信任级别。
    private ToolResult merge(ToolResult first, ToolResult second) {
        Set<Long> evidence = new LinkedHashSet<>(first.evidenceChunkIds());
        evidence.addAll(second.evidenceChunkIds());
        Set<Long> candidates = new LinkedHashSet<>(first.candidateChunkIds());
        candidates.addAll(second.candidateChunkIds());
        return new ToolResult("<SEMANTIC_EVIDENCE>\n" + first.text() + "\n</SEMANTIC_EVIDENCE>\n\n"
                + second.text(), evidence, candidates);
    }

    // 优先返回可验证语义关系，找不到时才使用混合检索扩大调查范围。
    private ToolResult semanticFirst(String tool, CodeChunk current, List<CodeChunk> chunks,
                                     String query, int limit, VulnerabilityType vulnerabilityType) {
        ToolResult semantic = semantic(tool, current, limit, vulnerabilityType);
        if (!semantic.evidenceChunkIds().isEmpty()) return semantic;
        return merge(semantic, search(current, chunks, query, limit));
    }

    // 执行混合检索并明确把结果标为必须继续验证关系的候选证据。
    private ToolResult search(CodeChunk current, List<CodeChunk> chunks, String query, int limit) {
        Set<String> symbols = splitSymbols(current.getCalledSymbols());
        RagService.RetrievalRequest request = new RagService.RetrievalRequest(current.getTaskId(), current.getId(),
                query, current.getEndpoint(), current.getFilePath(), symbols, limit);
        List<RagService.RetrievedCode> results = ragService.retrieveDetailed(chunks, request);
        return new ToolResult("[RAG_CANDIDATE] 以下结果只能用于发现线索；必须调用 verify_relation 验证后才能引用。\n\n"
                + results.stream().map(item -> format(item.chunk(), item.reason(), item.score()))
                .collect(Collectors.joining("\n\n")),
                Set.of(), results.stream().map(item -> item.chunk().getId())
                .collect(Collectors.toCollection(LinkedHashSet::new)));
    }

    // 从同文件和精确调用符号中提取当前目标的直接上下文。
    private ToolResult callContext(CodeChunk current, List<CodeChunk> chunks, int limit) {
        Set<String> called = splitSymbols(current.getCalledSymbols());
        String currentMethod = methodName(current.getSymbolName());
        List<CodeChunk> results = chunks.stream().filter(chunk -> !chunk.getId().equals(current.getId()))
                .filter(chunk -> current.getFilePath().equals(chunk.getFilePath())
                        || called.contains(methodName(chunk.getSymbolName()))
                        || splitSymbols(chunk.getCalledSymbols()).contains(currentMethod))
                .sorted(Comparator.comparing((CodeChunk chunk) -> !current.getFilePath().equals(chunk.getFilePath()))
                        .thenComparing(CodeChunk::getStartLine))
                .limit(limit).toList();
        return new ToolResult(results.stream().map(chunk -> format(chunk, "调用或同文件关系", 1.0))
                .collect(Collectors.joining("\n\n")), ids(results));
    }

    // 按 ID 读取源码块，但只有当前目标可立即进入允许证据集合。
    private ToolResult getChunk(String query, CodeChunk current, List<CodeChunk> chunks) {
        Long id = current.getId();
        try {
            if (query != null && !query.isBlank()) id = Long.parseLong(query.replaceAll("[^0-9]", ""));
        } catch (Exception ignored) {
            // 无法解析时读取当前块。
        }
        Long selectedId = id;
        CodeChunk result = chunks.stream().filter(chunk -> selectedId.equals(chunk.getId())).findFirst().orElse(current);
        if (result.getId().equals(current.getId())) {
            return new ToolResult(format(result, "当前审计目标", 1.0), Set.of(result.getId()));
        }
        return new ToolResult("[RAG_CANDIDATE] 读取候选源码不等于证明关系。\n"
                + format(result, "按ID读取候选", 1.0), Set.of(), Set.of(result.getId()));
    }

    // 通过语义图或确定性结构关系把 RAG 候选提升为已验证证据。
    private ToolResult verifyRelation(String query, CodeChunk current, List<CodeChunk> chunks) {
        Long candidateId = parseChunkId(query);
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
                + format(candidate, "确定性关系验证通过", 1.0), Set.of(candidateId), Set.of());
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

    private Long parseChunkId(String query) {
        if (query == null) return null;
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("\\d+").matcher(query);
        if (!matcher.find()) return null;
        try { return Long.parseLong(matcher.group()); } catch (NumberFormatException exception) { return null; }
    }

    // 将源码包裹为不可信代码片段，避免其文本被当作 Agent 指令执行。
    private String format(CodeChunk chunk, String reason, double score) {
        String code = chunk.getContent().substring(0, Math.min(chunk.getContent().length(), 4_000));
        return "CHUNK_ID=" + chunk.getId() + " | " + chunk.getFilePath() + ":" + chunk.getStartLine()
                + " | " + chunk.getSymbolName() + " | reason=" + reason + " | score="
                + String.format(Locale.ROOT, "%.3f", score) + "\n<UNTRUSTED_CODE>\n" + code
                + "\n</UNTRUSTED_CODE>";
    }

    private Set<Long> ids(List<CodeChunk> chunks) {
        return chunks.stream().map(CodeChunk::getId).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private Set<String> splitSymbols(String value) {
        if (value == null || value.isBlank()) return Set.of();
        return Arrays.stream(value.split(",")).map(String::strip).filter(item -> !item.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private String methodName(String symbol) {
        if (symbol == null) return "";
        int hash = symbol.lastIndexOf('#');
        return hash < 0 ? symbol : symbol.substring(hash + 1);
    }

    private String append(String query, String suffix) {
        return (query == null ? "" : query) + " " + suffix;
    }

    public record ToolResult(String text, Set<Long> evidenceChunkIds, Set<Long> candidateChunkIds) {
        public ToolResult(String text, Set<Long> evidenceChunkIds) {
            this(text, evidenceChunkIds, Set.of());
        }

        public ToolResult {
            text = text == null || text.isBlank() ? "未检索到相关代码" : text;
            evidenceChunkIds = evidenceChunkIds == null ? Set.of() : Set.copyOf(evidenceChunkIds);
            candidateChunkIds = candidateChunkIds == null ? Set.of() : Set.copyOf(candidateChunkIds);
        }
    }
}
