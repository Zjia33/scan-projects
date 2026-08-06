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
    public static final String SEARCH_SYMBOLS = "search_symbols";
    public static final String SEARCH_CODE = "search_code";
    public static final String EXPLORE_CALL_GRAPH = "explore_call_graph";
    public static final String READ_VERIFIED_RELATIONS = "read_verified_relations";
    public static final String GET_CHANGE_CONTEXT = "get_change_context";
    public static final String RESOLVE_DATA_ACCESS = "resolve_data_access";
    public static final String INSPECT_SECURITY_POLICY = "inspect_security_policy";
    public static final String TRACE_VALUE = "trace_value";

    private static final List<ToolSpec> SPECS = List.of(
            spec(READ_SOURCE, Set.of("chunkId", "startLine", "endLine", "contextLines", "limit"),
                    Set.of("chunkId"), "读取目标或已发现候选源码；普通搜索候选读取后仍不会自动成为证据。",
                    "chunkId=代码块数字 ID；startLine/endLine=文件绝对行号，必须位于代码块范围内；"
                            + "contextLines=指定范围前后附加行数，0..10，默认2；limit=兼容性参数，源码读取按一次调用返回，"
                            + "过长内容会明确标记为受限；需要更少内容时缩小 startLine/endLine"),
            spec(SEARCH_SYMBOLS, Set.of("symbol", "kind", "annotation", "filePath", "endpoint",
                            "text", "limit", "anchorChunkId"), Set.of(),
                    "按符号、注解、文件、端点或文本执行确定性结构搜索；至少提供一个检索条件。",
                    "symbol=类名、方法名或完整符号；kind=符号类型；annotation=注解名；filePath=目标文件路径片段；"
                            + "endpoint=接口路径；text=符号元数据或源码中的文本；"
                            + "anchorChunkId=已确认证据代码块，用于限定搜索锚点；limit=返回结果数，1..10"),
            spec(SEARCH_CODE, Set.of("query", "scope", "filePattern", "includeTests", "caseSensitive",
                            "contextLines", "depth", "limit", "anchorChunkId"), Set.of("query"),
                    "在当前文件、已确认关联范围或 Target 项目内执行字面量源码搜索；结果默认只是候选。",
                    "query=非空字面量，最长200字符；scope=CURRENT_FILE、RELATED 或 PROJECT，默认RELATED；"
                            + "filePattern=可选文件 glob；includeTests=是否包含测试目录，默认false；caseSensitive=是否区分大小写，默认false；"
                            + "contextLines=命中行前后上下文，0..5，默认2；depth=RELATED 搜索的关联深度，1..5，默认2；"
                            + "anchorChunkId=已确认证据锚点；limit=结果数，1..10；超出 limit 的结果不会继续返回，PROJECT 结果会按需物化但仍是候选"),
            spec(EXPLORE_CALL_GRAPH, Set.of("direction", "depth", "targetChunkId", "targetSymbol",
                            "limit", "anchorChunkId"), Set.of(),
                    "查看 CodeGraph 直接调用者/被调用者符号候选，并补充框架语义边；不读取候选源码。",
                    "direction=CALLERS、CALLEES 或 BOTH，默认BOTH；depth=框架语义探索深度，1..5，默认3；"
                            + "targetChunkId=当前任务中的目标代码块数字 ID；targetSymbol=目标符号文本，二者用于筛选框架语义关系；"
                            + "CodeGraph 普通调用关系始终以当前 anchorChunkId（未提供时为当前审查代码块）为起点；"
                            + "anchorChunkId=已确认证据锚点；limit=候选数，1..10；超出 limit 的关系不会继续返回；"
                            + "CodeGraph 返回的 candidateId 只能交给 read_verified_relations"),
            spec(READ_VERIFIED_RELATIONS, Set.of("candidateIds", "anchorChunkId"), Set.of("candidateIds"),
                    "物化并读取一个或多个 CodeGraph 候选源码；服务端自动确认候选来源和 Target 唯一映射后返回证据。",
                    "candidateIds=explore_call_graph 或首次预取结果中的位置标识数组，不是代码块数字 ID；可以只传一个 ID，一次最多 10 个；"
                            + "anchorChunkId=可选的已确认证据锚点，必须与候选查询锚点一致；"
                            + "返回 evidenceChunkIds 后可用于 FINDING 和后续 anchorChunkId"),
            spec(GET_CHANGE_CONTEXT, Set.of("selector", "includeConfiguration", "limit", "anchorChunkId"), Set.of(),
                    "读取当前任务的 Base/Target 方法级和文件级变更。",
                    "selector=可选文件路径、方法名或变更标识，用于筛选相关变化；includeConfiguration=是否包含配置文件变化，默认true；"
                            + "anchorChunkId=已确认证据锚点；limit=返回方法变化和文件变化的数量上限，1..10"),
            spec(RESOLVE_DATA_ACCESS, Set.of("selector", "depth", "limit", "anchorChunkId"), Set.of(),
                    "解析与当前目标相关的 Mapper、Repository、SQL、参数绑定和持久化边界。",
                    "selector=可选类名、方法名、表名或 SQL 片段；depth=关系搜索深度，1..5，默认3；"
                            + "anchorChunkId=已确认证据锚点；limit=返回结果数，1..10；直接关联结果可作为语义证据，未关联命中仍是候选"),
            spec(INSPECT_SECURITY_POLICY, Set.of("endpoint", "limit", "anchorChunkId"), Set.of(),
                    "检查当前方法注解以及匹配入口的全局安全策略。",
                    "endpoint=可选接口路径，缺省时使用当前代码块 endpoint；anchorChunkId=已确认证据锚点；"
                            + "limit=最多检查的策略条目数，1..10；未发现策略不等于已证明入口无保护"),
            spec(TRACE_VALUE, Set.of("source", "sink", "variable", "depth", "limit", "anchorChunkId"), Set.of(),
                    "追踪值来源、危险终点、跨调用参数映射、持久化安全流及路径上的 Guard。",
                    "source=来源方法、字段或输入名；sink=危险操作或输出名；variable=变量名；至少提供一个可缩小结果，全部省略时按当前目标漏洞类型查询已索引流；"
                            + "depth=跨方法追踪深度，1..5，默认3；anchorChunkId=已确认证据锚点；limit=路径或映射数，1..10；"
                            + "未找到路径不能证明不存在数据流")
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
        return "工具说明：所有工具都是只读查询。candidateId 是 explore_call_graph 返回的 CodeGraph 位置标识，"
                + "不是数字 chunkId；chunkId 是当前 Target 代码块的数字 ID。工具每次调用只返回一个受控结果集。"
                + "可用工具：" + SPECS.stream().map(ToolSpec::promptLine)
                .collect(Collectors.joining("；")) + "。"
                + "只有当前审计目标或服务端自动确认的 evidenceChunkId 才能作为 anchorChunkId；"
                + "CodeGraph 候选读取后会由服务端自动确认来源和 Target 映射，本地调用复验只作为质量标记，不会单独否决候选。"
                + "参数名不区分大小写；各工具的 limit 通常为1..10（源码读取工具的 limit 仅为兼容字段）；"
                + "结果被 limit 或安全字符上限限制时会标记结果范围受限；应缩小 selector、query、direction 或 depth，"
                + "不能把未返回内容解释为不存在。PARTIAL_SCOPE 或 ERROR 也表示覆盖不完整，禁止据此否决漏洞。";
    }

    private static ToolSpec spec(String name, Set<String> arguments, Set<String> requiredArguments,
                                 String description, String argumentGuide) {
        return new ToolSpec(name, arguments, requiredArguments, description, argumentGuide);
    }

    public record ToolSpec(String name, Set<String> allowedArguments, Set<String> requiredArguments,
                           String description, String argumentGuide) {
        public ToolSpec {
            allowedArguments = Set.copyOf(allowedArguments);
            requiredArguments = requiredArguments == null ? Set.of() : Set.copyOf(requiredArguments);
            description = description == null ? "" : description;
            argumentGuide = argumentGuide == null ? "" : argumentGuide;
        }

        public ToolSpec(String name, Set<String> allowedArguments, String description) {
            this(name, allowedArguments, Set.of(), description, "");
        }

        String promptLine() {
            String required = requiredArguments.isEmpty() ? "" : "必填="
                    + requiredArguments.stream().sorted().collect(Collectors.joining(",")) + "；";
            return name + "({" + allowedArguments.stream().sorted().collect(Collectors.joining(","))
                    + "})" + description + " 参数：" + required + argumentGuide;
        }
    }
}
