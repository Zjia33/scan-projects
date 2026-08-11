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
    public static final String GET_CHANGE_CONTEXT = "get_change_context";
    public static final String RESOLVE_DATA_ACCESS = "resolve_data_access";
    public static final String INSPECT_SECURITY_POLICY = "inspect_security_policy";
    public static final String TRACE_VALUE = "trace_value";

    private static final List<ToolSpec> SPECS = List.of(
            spec(READ_SOURCE, Set.of("chunkId", "startLine", "endLine", "contextLines"),
                    """
                    用途：读取当前会话中已验证或已发现候选代码块的真实源码，适合精读危险语句及其附近上下文。
                    参数：chunkId(long，必填)；startLine/endLine(int，可选，必须位于该代码块范围内；只填 startLine 时默认读取该行)；contextLines(int，0..10，默认2)。
                    结果：读取已验证代码块时仍是证据；读取候选只返回 UNVERIFIED_CANDIDATE，不会因为读取而自动成为证据。单次最多返回80行，截断后应缩小行号范围继续读取。
                    """),
            spec(VERIFY_RELATION, Set.of("candidateChunkId", "anchorChunkId"),
                    """
                    用途：验证一个已由搜索、调用图或语义工具发现的候选代码块，是否与当前目标或已验证证据存在可靠调用、语义流或安全策略关系。
                    参数：candidateChunkId(long，必填，必须来自 candidateChunkIds/UNVERIFIED_CANDIDATE)；anchorChunkId(long，可选，省略时使用当前目标；填写时只能是已验证 evidenceChunkId)。
                    结果：VERIFIED_EVIDENCE 才表示候选已提升为可引用证据；RELATION_REJECTED 表示仍只能作为上下文。不得用它验证猜测出来的代码块 ID，也不得用未验证候选作为 anchorChunkId。
                    """),
            spec(SEARCH_SYMBOLS, Set.of("symbol", "kind", "annotation", "filePath", "endpoint",
                            "text", "limit", "cursor", "anchorChunkId"),
                    """
                    用途：按结构化元数据定位类、方法、注解、文件或接口，适合已知名称或安全注解时查找定义；不是源码字面量搜索。
                    参数：symbol/kind/annotation/filePath/endpoint/text(string，至少填写一个；同时填写时按组合条件过滤)；limit(int，1..10，默认6)；cursor(long，可选，分页时原样使用上次 nextCursor)；anchorChunkId(long，可选，仅允许已验证证据)。
                    结果：除当前锚点外的匹配通常是 UNVERIFIED_CANDIDATE；若 truncated=true，使用 nextCursor 继续，不要自行计算游标。
                    """),
            spec(SEARCH_CODE, Set.of("query", "scope", "filePattern", "includeTests", "caseSensitive",
                            "contextLines", "depth", "limit", "cursor", "anchorChunkId"),
                    """
                    用途：对真实源码执行字面量搜索，适合查找调用、字段名、配置键或危险 API；不支持正则表达式。
                    参数：query(string，必填，非空且最长200字符)；scope(string，可选枚举 CURRENT_FILE|RELATED|PROJECT，默认RELATED)；filePattern(string，可选 glob)；includeTests(boolean，默认false)；caseSensitive(boolean，默认false)；contextLines(int，0..5，默认2)；depth(int，1..5，默认2，仅RELATED有效)；limit(int，1..10，默认6)；cursor(long，可选，原样使用 nextCursor)；anchorChunkId(long，可选，仅允许已验证证据)。
                    结果：当前锚点内匹配可保留原证据属性，其他匹配均是 UNVERIFIED_CANDIDATE；需要写入 FINDING 时先 verify_relation。
                    """),
            spec(EXPLORE_CALL_GRAPH, Set.of("direction", "depth", "targetChunkId", "targetSymbol",
                            "limit", "anchorChunkId"),
                    """
                    用途：从锚点探索可靠调用路径；查入口使用 CALLERS，查下游危险操作使用 CALLEES，方向不确定才使用 BOTH。
                    参数：direction(string，可选枚举 CALLERS|CALLEES|BOTH，默认BOTH)；depth(int，1..5，默认3)；targetChunkId(long，可选，优先于 targetSymbol)；targetSymbol(string，可选)；limit(int，1..10，默认6)；anchorChunkId(long，可选，仅允许已验证证据)。
                    结果：CALL_GRAPH/CODEGRAPH_RELATIONS 中明确返回的关系代码块属于 evidenceChunkIds，可作为调用链证据；无路径不等于不存在调用，只表示当前索引范围内未解析到。
                    """),
            spec(GET_CHANGE_CONTEXT, Set.of("selector", "includeConfiguration", "limit", "anchorChunkId"),
                    """
                    用途：核对 Base/Target 方法或文件差异，判断漏洞是 NEW、PERSISTING，还是仅由影响范围纳入；不要用它代替 target.codeExcerpt 中已经提供的当前变更。
                    参数：selector(string，可选，可填写方法名、符号、文件路径或变更特征关键词)；includeConfiguration(boolean，默认true)；limit(int，1..10，默认6)；anchorChunkId(long，可选，仅允许已验证证据)。
                    结果：当前文件内的变更可作为证据；其他文件变更可能是 UNVERIFIED_CANDIDATE，引用前需 verify_relation。差异中的 - 为 Base、+ 为 Target，B/T 标签是实际旧/新行号。
                    """),
            spec(RESOLVE_DATA_ACCESS, Set.of("selector", "depth", "limit", "anchorChunkId"),
                    """
                    用途：沿调用关系解析 Mapper、Repository、DAO、SQL 和参数绑定，适合确认真实数据访问、查询构造和对象范围。
                    参数：selector(string，可选，可填写表名、Mapper/Repository 方法、SQL 关键词或字段名)；depth(int，1..5，默认3)；limit(int，1..10，默认6)；anchorChunkId(long，可选，仅允许已验证证据)。
                    结果：调用范围内解析到的结果标记为 SEMANTIC_EVIDENCE；仅靠项目范围搜索发现的结果是 UNVERIFIED_CANDIDATE，必须先 verify_relation。单个语法指标本身不能直接证明漏洞。
                    """),
            spec(INSPECT_SECURITY_POLICY, Set.of("endpoint", "limit", "anchorChunkId"),
                    """
                    用途：检查方法安全注解、过滤器/拦截器和能够匹配入口的全局安全规则，适合核对授权缺失或安全控制是否实际生效。
                    参数：endpoint(string，可选，省略时使用锚点 endpoint)；limit(int，1..10，默认6)；anchorChunkId(long，可选，仅允许已验证证据)。
                    结果：方法注解、endpoint 规则匹配或直接调用关联可成为已验证策略证据；普通项目级安全配置只是 UNVERIFIED_CANDIDATE。未发现策略不等于已经证明入口无保护，仍需结合 Recon 的框架启用事实。
                    """),
            spec(TRACE_VALUE, Set.of("source", "sink", "variable", "depth", "limit", "anchorChunkId"),
                    """
                    用途：追踪外部输入、敏感值或业务字段到危险终点的路径，并核对跨调用参数映射和路径 Guard。
                    参数：source/sink/variable(string，可选，至少优先填写最明确的一项；全部省略时返回当前漏洞类型下与锚点相关的已有流)；depth(int，1..5，默认3)；limit(int，1..10，默认6)；anchorChunkId(long，可选，仅允许已验证证据)。
                    结果：VALUE_TRACE/ARGUMENT_MAPPING 中返回的是已解析语义证据；没有结果只表示当前分析未解析到满足条件的数据流，不能单独作为漏洞不存在的反证。
                    """)
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
        return """

                工具调用说明：
                - 只能调用下列只读工具；arguments 只能包含对应工具列出的字段，禁止增加自定义参数。
                - long/int 必须使用 JSON 数字，boolean 必须使用 true/false；省略可选参数时使用说明中的默认值。
                - anchorChunkId 省略时使用当前调查目标；填写时必须来自当前目标或已验证 evidenceChunkIds。UNVERIFIED_CANDIDATE 不能直接作为锚点或 FINDING 证据，必须先 verify_relation。
                - TOOL_RESULT 的 status=INVALID/DENIED/ERROR 表示本次调用未形成证据；不得把错误说明当作代码事实。truncated=true 时仅对支持 cursor 的搜索工具原样传回 nextCursor，其他工具应缩小条件重试。
                - VERIFIED_EVIDENCE、SEMANTIC_EVIDENCE、CODEGRAPH_RELATIONS 及工具返回的 evidenceChunkIds 可以进入证据链；UNVERIFIED_CANDIDATE/candidateChunkIds 只能作为线索。

                可用工具：
                """ + SPECS.stream().map(ToolSpec::promptLine)
                .collect(Collectors.joining("\n\n")) + "\n\n";
    }

    private static ToolSpec spec(String name, Set<String> arguments, String description) {
        return new ToolSpec(name, arguments, description);
    }

    public record ToolSpec(String name, Set<String> allowedArguments, String description) {
        public ToolSpec {
            allowedArguments = Set.copyOf(allowedArguments);
        }

        String promptLine() {
            return name + "\n允许参数：{" + allowedArguments.stream().sorted().collect(Collectors.joining(", "))
                    + "}\n" + description.strip();
        }
    }
}
