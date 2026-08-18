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
                    读取已知代码块的真实源码和行号；不负责搜索，也不验证代码块关系。已知类、方法、注解、文件路径或接口路径时，先用 search_symbols 取得 chunkId，再用本工具精读。
                    参数：chunkId(long，必填)必须来自 target/evidenceChunkIds/candidateChunkIds；startLine/endLine(int，可选)是该代码块范围内的文件绝对行号，只填 startLine 时读取该行，都不填时读取整个块；contextLines(int，0..20，默认2)附加两侧上下文。
                    返回：>>> 标记请求行；最多160行且无 cursor。候选读取后仍是 candidateChunkIds；truncated=true 时缩小行号范围。
                    示例 arguments：{"chunkId":1234,"startLine":86,"endLine":92,"contextLines":2}（示例数字必须替换）。
                    """),
            spec(VERIFY_RELATION, Set.of("candidateChunkId", "anchorChunkId"),
                    """
                    将最终需要引用或作为新锚点的候选，与已验证锚点核对调用、语义或策略关系；它不直接证明漏洞成立。
                    参数：candidateChunkId(long，必填)取自 candidateChunkIds；anchorChunkId(long，可选)取自 target/evidenceChunkIds，省略时为最初目标。未知 ID 或以候选作锚点会被拒绝。
                    返回：只有 status=OK、VERIFIED_EVIDENCE 且候选进入 evidenceChunkIds 才验证通过；RELATION_REJECTED/status=DENIED 时仍是候选。结果不含源码，按需再 read_source。
                    示例 arguments：{"candidateChunkId":2234,"anchorChunkId":1234}（示例数字必须替换）。
                    """),
            spec(SEARCH_SYMBOLS, Set.of("symbol", "kind", "annotation", "filePath", "endpoint",
                            "limit", "cursor", "anchorChunkId"),
                    """
                    已知类名、方法名、注解、文件路径、接口路径或代码块类型时优先使用本工具，再用 read_source 精读；不要先用 search_code 猜定义。它按本地语义索引和完整 Target CodeGraph 索引定位定义并取得 chunkId，不搜索普通变量使用、字符串或配置字面量。提供 symbol 时会执行 CodeGraph 名称查询并按需物化尚未加载的候选位置。以下字符串均为不区分大小写的子串，至少填一项，多项为 AND：
                    - symbol：类/方法/Class#method/限定名/签名片段，如 "OrderService#load"；不要传 "service.load(id)"。
                    - kind：优先复用 target.chunkType 或结果 kind；常见 "JAVA_METHOD"、"TEXT_XML"、"MYBATIS_SQL"、"TEMPLATE_SINK"，不是固定枚举。
                    - annotation：注解名或稳定片段，如 "PreAuthorize"；不要传自然语言。
                    - filePath：使用 / 的项目相对路径或片段，如 "OrderService.java"。
                    - endpoint：路由路径或片段，如 "/orders/{id}"；不含 HTTP 方法和域名。
                    limit/cursor/anchorChunkId 遵循通用规则。CodeGraph kind 会由常见本地类型转换为 method/class 等固定类型；annotation、filePath、endpoint 仍由本地元数据过滤。返回元数据和 CODEGRAPH_QUERY 覆盖摘要，不含源码；锚点外结果是 candidateChunkIds，未映射位置不会伪造 ID。
                    示例 arguments：{"symbol":"OrderService#load","kind":"JAVA_METHOD","limit":5}。
                    """),
            spec(SEARCH_CODE, Set.of("query", "scope", "filePattern", "includeTests", "caseSensitive",
                            "contextLines", "depth", "limit", "cursor", "anchorChunkId"),
                    """
                    仅在目标不能通过类名、方法名、注解、文件路径或接口路径结构化定位时，搜索当前任务已有代码块中每行源码的单个字面量。适合普通变量/字段使用、字符串、配置键、危险 API 文本或未知使用位置；已知结构化目标应使用 search_symbols -> read_source。它不支持正则、自然语言问题、备选词表达式或跨行片段。
                    参数：query(string，必填，1..500字符，如 "permitAll"、"tenant_id"、"${")；scope(string，CURRENT_FILE|RELATED|PROJECT，默认RELATED)，分别表示锚点文件、锚点文件加可靠调用图范围、全项目；filePattern(string，可选 glob，支持 *、**、?，如 "**/*Security*.java")；includeTests(boolean，默认false)；caseSensitive(boolean，默认false)；contextLines(int，0..5，默认2)；depth(int，1..5，默认2，仅RELATED有效)；limit/cursor/anchorChunkId 遵循通用规则。
                    返回：>>> 标记命中行，相交或相邻的上下文窗口会合并；只有锚点命中保留证据资格，其他结果是 candidateChunkIds。
                    示例 arguments：{"query":"permitAll","scope":"PROJECT","filePattern":"**/*Security*.java","limit":5}。
                    """),
            spec(EXPLORE_CALL_GRAPH, Set.of("direction", "depth", "targetChunkId",
                            "limit", "anchorChunkId"),
                    """
                    查询调用者、被调用者或到指定代码块的调用路径；调用可达不等于值可控或漏洞成立。
                    参数：direction(string，CALLERS|CALLEES|BOTH，默认BOTH，相对锚点；上游/下游/双向)；depth(int，1..3，默认2，最大调用边数)；targetChunkId(long，可选，来自已出现的真实代码块 ID，未知时先 search_symbols)；limit/anchorChunkId 遵循通用规则。
                    返回：本地语义边和 CodeGraph 邻居在同一 BFS 中按 depth 逐层展开；每个节点包含 chunkId、symbol、filePath:startLine，已定位的边包含 line 和不可信调用表达式摘要。VERIFIED 边的可达节点进入 evidenceChunkIds；CANDIDATE 边或经过未验证边才到达的节点进入 candidateChunkIds。未映射位置会按需物化为可读取 Chunk；完整源码用 read_source，EMPTY 不等于不存在调用。
                    示例 arguments：{"direction":"CALLEES","targetChunkId":2234,"depth":3,"limit":5}。
                    """),
            spec(GET_CHANGE_CONTEXT, Set.of("selector", "includeConfiguration", "limit", "anchorChunkId"),
                    """
                    仅用于增量调查；target.codeExcerpt 已含当前 CHANGED 差异，不要重复查询当前正文。
                    参数：selector(string，可选)：查方法变化时用方法名/Class#method/路径，只匹配 Base/Target 路径、符号和方法名；查文件变化时还可用 changeType 或 diff 字面量，多词为 OR。includeConfiguration(boolean，默认false)仅在 selector 省略时附加配置变化索引，不返回其 diff；limit 是方法与文件结果总数；anchorChunkId 遵循通用规则。
                    返回：显式 selector 才返回其他方法/文件差异；文件最多返回3个相关 hunk。- 为 Base、+ 为 Target，B/T 为实际旧/新行号；其他变化块是 candidateChunkIds。
                    示例 arguments：{"selector":"application.yml","limit":5}；仅列配置索引用 {"includeConfiguration":true,"limit":5}。
                    """),
            spec(RESOLVE_DATA_ACCESS, Set.of("selector", "depth", "limit", "anchorChunkId"),
                    """
                    定位 Mapper/Repository/DAO/SQL、参数绑定和 tenant/owner 约束；语法指标本身不能确认或排除漏洞。
                    参数：selector(string，可选)用长度至少2的技术标识，如 "OrderMapper#selectById"、"tenant_id"、"${"；它在路径、符号、endpoint、类型、参数、注解、被调符号和源码中分词 OR 匹配，不要传自然语言。depth(int，1..5，默认3，沿可靠调用边双向扩展)；limit/anchorChunkId 遵循通用规则。
                    返回：优先返回可达范围内的 SEMANTIC_EVIDENCE；仅在完全没有可达结果时退回项目搜索并标记 UNVERIFIED_CANDIDATE。只含关键行及前后5行，完整查询用 read_source。
                    示例 arguments：{"selector":"tenant_id","depth":3,"limit":5}。
                    """),
            spec(INSPECT_SECURITY_POLICY, Set.of("endpoint", "limit", "anchorChunkId"),
                    """
                    检查锚点方法注解、requestMatchers、过滤器和拦截器；找到或未找到策略都不能单独证明控制生效或缺失。
                    参数：endpoint(string，可选)是实际请求路径，如 "/orders/42"，省略时使用锚点 endpoint；不含 HTTP 方法、域名或查询参数。limit/anchorChunkId 遵循通用规则；锚点方法注解占一个结果名额。
                    返回：先检查全部策略并排序，再应用 limit。endpoint 匹配或直接关联策略进入 evidenceChunkIds，普通项目配置进入 candidateChunkIds；结合 Recon 的框架启用和配置顺序判断。
                    示例 arguments：{"endpoint":"/orders/42","limit":5}。
                    """),
            spec(TRACE_VALUE, Set.of("source", "sink", "variable", "depth", "limit", "anchorChunkId"),
                    """
                    查询已有 source-to-sink 流或跨调用参数映射。source/sink 优先复用 semanticEvidence/TOOL_RESULT 中的描述子串，如 "HTTP parameter"、"Statement.execute"；variable 用标识符，如 "orderId"，不要编造自然语言。
                    参数：source/sink/variable(string，可选)：已有 SecurityFlow 中多项为 AND；无匹配流时只用首个非空项回退到参数映射，优先级 variable、source、sink。全部省略时先返回当前漏洞类型的已有流，否则返回参数映射。depth(int，1..5，默认3，仅参数映射回退有效)；limit/anchorChunkId 遵循通用规则。
                    返回：VALUE_TRACE 是完整语义流；ARGUMENT_MAPPING 只证明局部参数传递，不证明完整路径、可控性或 Guard 缺失。没有结果只表示当前分析未解析到满足条件的数据流，不能排除漏洞。
                    示例 arguments：{"variable":"orderId","depth":3,"limit":5}。
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

                工具选择：已知类/方法/注解/文件/接口时 search_symbols -> read_source；普通变量、字段使用、字符串、配置键或未知使用位置时 search_code；候选关系 verify_relation；调用路径 explore_call_graph；增量差异 get_change_context；数据访问 resolve_data_access；安全策略 inspect_security_policy；值流 trace_value。

                通用规则：
                - 先读 target、semanticEvidence、recon 和已有 observations；不要重复查询已给出的事实。工具均只读，arguments 只能含允许参数；string/整数/boolean 必须使用正确 JSON 类型。非法类型、范围或枚举返回 INVALID_ARGUMENT，不会自动转换、裁剪或回退。
                - anchorChunkId 省略时为最初目标；填写时只能来自 target/evidenceChunkIds。limit 为1..20、默认10。search_symbols/search_code 的 cursor 仅在 truncated=true 时原样回传 nextCursor 数值；游标只越过本次实际返回的结果，不要自行计算。
                - evidenceChunkIds/VERIFIED_EVIDENCE/SEMANTIC_EVIDENCE 可进入证据链；原始 CODEGRAPH_RELATIONS、UNVERIFIED_CANDIDATE/candidateChunkIds 只能作为线索，不能直接作为锚点或 FINDING 证据。候选流程：搜索 -> read_source 判断相关性 -> 需要引用时 verify_relation。
                - 证据资格不等于漏洞成立，仍须用源码证明输入、失效控制、危险操作和影响。EMPTY 不是反证；INVALID/DENIED/ERROR 不形成新证据。TOOL_RESULT_TRUNCATED、OBSERVATION_TRUNCATED、ITEM_TRUNCATED 表示结果不完整。
                - 下列示例中的 ID 和行号仅说明 JSON 类型，必须替换为当前输入或工具结果中的真实值。

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
