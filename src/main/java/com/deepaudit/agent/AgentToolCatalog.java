package com.deepaudit.agent;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** 工具名称、参数白名单和模型说明的唯一来源。 */
public final class AgentToolCatalog {
    public static final String READ_SOURCE = "read_source";
    public static final String VERIFY_RELATION = "verify_relation";
    public static final String SEARCH_SYMBOLS = "search_symbols";
    public static final String SEARCH_CODE = "search_code";
    public static final String EXPLORE_CALL_GRAPH = "explore_call_graph";
    public static final String READ_IMPACT_SOURCE = "read_impact_source";
    public static final String GET_CHANGE_CONTEXT = "get_change_context";
    public static final String RESOLVE_DATA_ACCESS = "resolve_data_access";
    public static final String INSPECT_SECURITY_POLICY = "inspect_security_policy";
    public static final String TRACE_VALUE = "trace_value";

    private static final List<ToolSpec> SPECS = List.of(
            spec(READ_SOURCE, Set.of("chunkId", "startLine", "endLine", "contextLines", "limit"),
                    "读取已验证或已发现候选源码；可用行号精读，读取候选不代表关系已验证"),
            spec(VERIFY_RELATION, Set.of("candidateChunkId", "anchorChunkId", "limit"),
                    "验证候选与已验证锚点的调用、语义流或安全策略关系"),
            spec(SEARCH_SYMBOLS, Set.of("symbol", "kind", "annotation", "filePath", "endpoint",
                            "text", "limit", "cursor", "anchorChunkId"),
                    "按符号、注解、文件或端点执行确定性结构搜索"),
            spec(SEARCH_CODE, Set.of("query", "scope", "filePattern", "includeTests", "caseSensitive",
                            "contextLines", "depth", "limit", "cursor", "anchorChunkId"),
                    "在当前文件、已验证关联范围或 Target 项目内执行字面量源码搜索；PROJECT 会按需物化命中位置，结果仅为候选"),
            spec(EXPLORE_CALL_GRAPH, Set.of("direction", "depth", "targetChunkId", "targetSymbol",
                            "limit", "cursor", "anchorChunkId"),
                    "分页查看直接调用者/被调用者符号候选，不预先读取候选源码"),
            spec(READ_IMPACT_SOURCE, Set.of("candidateId", "anchorChunkId", "limit"),
                    "按 candidateId 物化并读取一个 CodeGraph 候选源码；读取后仍需验证关系"),
            spec(GET_CHANGE_CONTEXT, Set.of("selector", "includeConfiguration", "limit", "anchorChunkId"),
                    "读取 Base/Target 方法和文件变更"),
            spec(RESOLVE_DATA_ACCESS, Set.of("selector", "depth", "limit", "anchorChunkId"),
                    "解析 Mapper、Repository、SQL 和参数绑定"),
            spec(INSPECT_SECURITY_POLICY, Set.of("endpoint", "limit", "anchorChunkId"),
                    "检查方法注解及匹配入口的全局安全规则"),
            spec(TRACE_VALUE, Set.of("source", "sink", "variable", "depth", "limit", "anchorChunkId"),
                    "追踪值、跨调用参数映射、持久化安全流及路径上的 Guard")
    );
    private static final Map<String, ToolSpec> BY_NAME = SPECS.stream().collect(Collectors.toMap(
            ToolSpec::name, value -> value, (left, right) -> left, LinkedHashMap::new));

    private AgentToolCatalog() {
    }

    static ToolSpec find(String name) {
        return name == null ? null : BY_NAME.get(name.toLowerCase(Locale.ROOT));
    }

    public static List<ToolSpec> specs() {
        return SPECS;
    }

    public static String prompt() {
        return "可用只读工具：" + SPECS.stream().map(ToolSpec::promptLine)
                .collect(Collectors.joining("；")) + "。"
                + "只有已验证 evidenceChunkId 才能作为 anchorChunkId，候选必须先 verify_relation。"
                + "各工具可用 limit:1..10；分页结果 truncated=true 且存在 nextCursor 时继续翻页；"
                + "PARTIAL_SCOPE、ERROR 或 truncated=true 且没有 nextCursor 表示覆盖不完整，禁止据此否决漏洞。";
    }

    private static ToolSpec spec(String name, Set<String> arguments, String description) {
        return new ToolSpec(name, arguments, description);
    }

    public record ToolSpec(String name, Set<String> allowedArguments, String description) {
        public ToolSpec {
            allowedArguments = Set.copyOf(allowedArguments);
        }

        String promptLine() {
            return name + "({" + allowedArguments.stream().sorted().collect(Collectors.joining(","))
                    + "})" + description;
        }
    }
}
