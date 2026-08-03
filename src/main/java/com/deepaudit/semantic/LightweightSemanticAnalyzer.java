package com.deepaudit.semantic;

import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.SecurityFlow;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.SemanticSymbol;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.source.AuditSourceFilter;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// 负责 LightweightSemanticAnalyzer 对应的确定性分析与事实提取。
@Slf4j
@Component
@RequiredArgsConstructor
public class LightweightSemanticAnalyzer {
    private static final Pattern MYBATIS_NAMESPACE = Pattern.compile("<mapper\\s+[^>]*namespace\\s*=\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern MYBATIS_STATEMENT = Pattern.compile("<(select|insert|update|delete)\\b[^>]*\\bid\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</\\1>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern SECURITY_POLICY = Pattern.compile("requestMatchers\\s*\\(([^)]*)\\)\\s*\\.\\s*(permitAll|authenticated|hasRole|hasAuthority)\\s*\\(([^)]*)\\)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern QUOTED = Pattern.compile("[\"']([^\"']+)[\"']");
    private static final Pattern SQL_DANGER = Pattern.compile("\\$\\{|(?:select|update|delete|insert)\\s+[^\\n;]*(?:\\+|concat\\s*\\()|create(?:native)?query\\s*\\([^\\n;]*\\+|statement\\s*\\.\\s*execute|execute(?:query|update)?\\s*\\([^)]*\\+", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern VALIDATION_BYPASS = Pattern.compile("skipverify|bypassverify|ignoreverification|verify\\w*\\s*\\([^;]+;\\s*(?!if)|catch\\s*\\([^)]*\\)\\s*\\{[^}]{0,300}(?:warn|ignore|continue)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern RAW_HTML = Pattern.compile("v-html|dangerouslySetInnerHTML|th:utext|innerHTML\\s*=|<%=|\\|\\s*safe", Pattern.CASE_INSENSITIVE);
    private static final Set<String> PERSISTED_TEXT_FIELDS = Set.of("content", "comment", "description", "notice", "nickname", "html", "body");

    private final SemanticAnalysisProperties properties;

    // 只解析增量作用域，并以 CodeGraph 候选拓扑约束跨方法关系。
    public Result analyze(UUID taskId, Path root, List<CodeChunk> chunks, Set<Long> scopeChunkIds,
                          List<CodeGraphIntegrationService.ScopedRelation> scopedRelations) throws IOException {
        // 第一阶段把作用域源码和 Recon 代码块转换成统一的内存程序模型。
        Program program = parseProgram(taskId, root, chunks, scopeChunkIds);
        // 第二阶段在调用方 AST 中验证 CodeGraph 候选关系，同时提取局部框架边界。
        buildScopedCallGraph(taskId, program, scopedRelations);
        // 第三阶段补充普通 Java 调用图无法直接表达的 Spring 事件发布到监听器关系。
        addSpringEventEdges(taskId, program);
        // 第四阶段按照 Mapper namespace 和 statement id 连接接口方法与 MyBatis XML SQL。
        addMyBatisEdges(taskId, program);
        // 第五阶段通过持久化字段名连接后端写入点与前端原始 HTML 输出点。
        addPersistenceEdges(taskId, program);
        // 第六阶段概括每个方法的返回依赖、敏感副作用和 Guard，并沿调用边向上游传播。
        buildMethodSummaries(program);
        // 第七阶段把边列表转换成 callerSymbolId 到出边列表，供后续广度优先搜索快速访问。
        program.buildOutgoing();
        // 第八阶段从全部代码块提取 Spring Security 路径规则，作为安全流上的全局 Guard 事实。
        List<SecurityPolicy> policies = extractSecurityPolicies(chunks);
        // 第九阶段从每个 HTTP 入口传播外部参数，生成受预算限制的 Source-to-Sink 调查路径。
        List<SecurityFlow> flows = buildSecurityFlows(taskId, program, policies);
        // 返回不可修改的结果快照，并把仅供内存遍历的 GraphEdge 转为可持久化调用边。
        return new Result(List.copyOf(program.symbols),
                program.edges.stream().map(GraphEdge::persisted).toList(), List.copyOf(flows), program.coverage());
    }

    // 配置 Java 17 符号求解器并把多类源码统一解析为程序节点。
    private Program parseProgram(UUID taskId, Path root, List<CodeChunk> chunks,
                                 Set<Long> scopeChunkIds) throws IOException {
        // Program 同时保存语义节点、AST 方法模型、调用边、索引和覆盖率计数器。
        Program program = new Program(root, chunks);
        // ReflectionTypeSolver 负责识别 JDK 与运行时可见类型，不用于加载或执行目标项目类。
        CombinedTypeSolver typeSolver = new CombinedTypeSolver();
        typeSolver.add(new ReflectionTypeSolver());
        // 每个项目源码根加入 JavaParserTypeSolver，使跨文件类名和方法签名能够被解析。
        for (Path sourceRoot : sourceRoots(root)) {
            try {
                typeSolver.add(new JavaParserTypeSolver(sourceRoot));
            } catch (RuntimeException exception) {
                log.debug("无法加入 JavaParser 源码根目录 {}", sourceRoot, exception);
            }
        }
        // JavaParser 固定使用 Java 17 语法，并把组合类型求解器安装为符号解析器。
        ParserConfiguration configuration = new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17)
                .setSymbolResolver(new JavaSymbolSolver(typeSolver));
        JavaParser parser = new JavaParser(configuration);

        // 只读取作用域 Chunk 所属 Java 文件，不再遍历 Target 构建第二套全项目调用图。
        Set<Path> javaFiles = chunks.stream()
                .filter(chunk -> chunk.getId() != null && scopeChunkIds.contains(chunk.getId()))
                .filter(chunk -> "JAVA_METHOD".equals(chunk.getChunkType())
                        || chunk.getFilePath().toLowerCase(Locale.ROOT).endsWith(".java"))
                .map(chunk -> root.resolve(chunk.getFilePath()).normalize())
                .filter(path -> path.startsWith(root.toAbsolutePath().normalize()))
                .filter(Files::isRegularFile)
                .filter(path -> AuditSourceFilter.shouldAnalyze(root, path))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        javaFiles.forEach(file -> parseJavaFile(taskId, root, file, parser, program, scopeChunkIds));
        // Java AST 之外再从 Recon 文本块补充 MyBatis SQL 与模板 Sink。
        parseMyBatisAndTemplates(taskId, root, chunks, program);
        // 所有节点收集完成后建立按完整签名、方法名和接口实现查询的内存索引。
        program.index();
        return program;
    }

    // 发现常见 Maven/Gradle 源码根目录，找不到时退回项目根目录。
    private List<Path> sourceRoots(Path root) throws IOException {
        List<Path> roots = new ArrayList<>();
        // 只加入生产源码根，防止测试类型和测试调用关系污染跨文件语义图。
        try (Stream<Path> paths = Files.walk(root)) {
            paths.filter(Files::isDirectory)
                    .filter(path -> AuditSourceFilter.shouldAnalyze(root, path))
                    .filter(path -> {
                        String value = normalized(path);
                        return value.endsWith("/java") && value.contains("/src/");
                    })
                    .forEach(roots::add);
        }
        // 非标准目录项目仍以项目根作为类型求解范围，保证分析可以继续。
        if (roots.isEmpty()) roots.add(root);
        return roots;
    }

    // 将 Java 类型和方法声明转换为可关联原始代码块的语义符号。
    private void parseJavaFile(UUID taskId, Path root, Path file, JavaParser parser, Program program,
                               Set<Long> scopeChunkIds) {
        try {
            // JavaParser 返回空结果表示语法恢复失败，此文件不生成 Java 语义节点。
            Optional<CompilationUnit> parsed = parser.parse(file).getResult();
            if (parsed.isEmpty()) return;
            CompilationUnit unit = parsed.get();
            // 数据库存储相对项目根的规范化路径，避免结果绑定扫描机器的绝对目录。
            String relative = normalized(root.relativize(file));
            // 同时遍历顶层类、内部类和接口，为每个声明建立所属类型模型。
            for (TypeDeclaration<?> declaration : unit.findAll(TypeDeclaration.class)) {
                // 优先使用符号求解得到完整类名，失败时根据 package 和声明名生成稳定回退名称。
                String owner = declaration.getFullyQualifiedName().orElseGet(() -> fallbackOwner(unit, declaration));
                TypeModel type = program.types.computeIfAbsent(owner,
                        ignored -> new TypeModel(owner, declaration.getNameAsString(), declaration));
                for (MethodDeclaration method : declaration.getMethods()) {
                    // 内部类型的方法会在其自己的 TypeDeclaration 轮次处理，这里避免被外层类型重复收集。
                    if (method.getParentNode().orElse(null) != declaration) continue;
                    if (method.getAnnotations().stream()
                            .map(annotation -> annotation.getNameAsString())
                            .anyMatch(AuditSourceFilter::isTestMethodAnnotation)) {
                        continue;
                    }
                    // 用文件和行号寻找 Recon 阶段的 JAVA_METHOD Chunk，建立语义节点到真实证据的联系。
                    CodeChunk chunk = program.findChunk(relative, line(method), "JAVA_METHOD");
                    if (chunk == null || chunk.getId() == null || !scopeChunkIds.contains(chunk.getId())) continue;
                    // 完整签名用于精确解析调用，符号求解失败时使用类名、方法名和参数类型回退。
                    String qualifiedName = resolvedSignature(method).orElseGet(() -> fallbackSignature(owner, method));
                    String parameters = method.getParameters().stream().map(parameter -> parameter.getTypeAsString())
                            .collect(Collectors.joining(","));
                    String annotations = declaration.getAnnotations().stream().map(Node::toString)
                            .collect(Collectors.joining(" ")) + " "
                            + method.getAnnotations().stream().map(Node::toString).collect(Collectors.joining(" "));
                    // SemanticSymbol 是后续落库对象，保存定位、接口、注解和截断后的方法源码摘要。
                    SemanticSymbol symbol = new SemanticSymbol(taskId, chunk == null ? null : chunk.getId(), "JAVA_METHOD",
                            qualifiedName, method.getNameAsString(), owner, method.getDeclarationAsString(false, false, true),
                            method.getTypeAsString(), parameters, relative, line(method), endLine(method),
                            chunk == null ? null : chunk.getEndpoint(), annotations.strip(), truncate(method.toString(), 12_000));
                    // MethodModel 额外保留 AST、所属类型和参数列表，仅在本次内存分析中使用。
                    MethodModel model = new MethodModel(symbol, method, type,
                            method.getParameters().stream().map(parameter -> parameter.getNameAsString()).toList(),
                            method.getParameters().stream().map(parameter -> simpleType(parameter.getTypeAsString())).toList());
                    type.methods.add(model);
                    program.methods.add(model);
                    program.symbols.add(symbol);
                }
            }
        } catch (Exception exception) {
            // 单个文件解析失败只降低调用图覆盖率，不中断对项目其他文件的分析。
            log.warn("语义分析跳过无法解析的 Java 文件: {}", file, exception);
        }
    }

    // 补充 MyBatis SQL 节点与模板原始 HTML Sink，覆盖非 Java 语义对象。
    private void parseMyBatisAndTemplates(UUID taskId, Path root, List<CodeChunk> chunks, Program program) {
        // 非 Java 结构直接复用 Recon 已读取的 Chunk，避免再次遍历和读取同一批文本文件。
        for (CodeChunk chunk : chunks) {
            String content = chunk.getContent() == null ? "" : chunk.getContent();
            if (chunk.getFilePath().toLowerCase(Locale.ROOT).endsWith(".xml")) {
                // 只有存在 MyBatis mapper namespace 的 XML 才继续解析 SQL statement。
                Matcher namespace = MYBATIS_NAMESPACE.matcher(content);
                if (namespace.find()) {
                    Matcher statement = MYBATIS_STATEMENT.matcher(content);
                    while (statement.find()) {
                        // statement 在 Chunk 内的偏移量换算成项目文件中的真实起始行。
                        int start = chunk.getStartLine() + countLines(content, statement.start());
                        String id = statement.group(2);
                        String details = statement.group(3).strip();
                        SemanticSymbol symbol = new SemanticSymbol(taskId, chunk.getId(), "MYBATIS_SQL",
                                namespace.group(1) + "." + id, id, namespace.group(1), statement.group(1).toUpperCase(Locale.ROOT),
                                "SQL", "", chunk.getFilePath(), start, start + countLines(statement.group(), statement.group().length()),
                                null, "", truncate(details, 12_000));
                        // namespace 和 statement id 稍后用于与同名 Mapper 接口方法建立精确边。
                        SqlModel sql = new SqlModel(symbol, namespace.group(1), id);
                        program.sqlStatements.add(sql);
                        program.symbols.add(symbol);
                    }
                }
            }
            // 非 Java Chunk 出现原始 HTML 渲染语法时，将其建模为存储型 XSS 的候选 Sink。
            if (!"JAVA_METHOD".equals(chunk.getChunkType()) && RAW_HTML.matcher(content).find()) {
                SemanticSymbol symbol = new SemanticSymbol(taskId, chunk.getId(), "TEMPLATE_SINK",
                        chunk.getFilePath() + "#" + chunk.getStartLine(), chunk.getSymbolName(), chunk.getFilePath(),
                        "RAW_HTML_RENDER", "HTML", "", chunk.getFilePath(), chunk.getStartLine(), chunk.getEndLine(),
                        null, "", truncate(content, 12_000));
                program.artifacts.add(new ArtifactModel(symbol));
                program.symbols.add(symbol);
            }
        }
    }

    // 用调用方局部 AST 独立验证 CodeGraph 候选关系，不再解析第二套全局调用拓扑。
    private void buildScopedCallGraph(UUID taskId, Program program,
                                      List<CodeGraphIntegrationService.ScopedRelation> scopedRelations) {
        Map<Long, List<CodeGraphIntegrationService.ScopedRelation>> byCaller = scopedRelations.stream()
                .filter(relation -> relation.callerChunkId() != null && relation.calleeChunkId() != null)
                .collect(Collectors.groupingBy(CodeGraphIntegrationService.ScopedRelation::callerChunkId,
                        LinkedHashMap::new, Collectors.toList()));
        Set<String> verifiedRelations = new LinkedHashSet<>();

        for (MethodModel caller : program.methods) {
            Map<String, String> variableTypes = variableTypes(caller);
            List<MethodCallExpr> calls = caller.declaration.findAll(MethodCallExpr.class).stream()
                    .sorted(Comparator.comparingInt(this::line).thenComparingInt(this::column)).toList();
            for (MethodCallExpr call : calls) {
                program.totalCallSites++;
                Map<String, Set<Integer>> dependencies = variableDependencies(caller, call);
                Map<Integer, Set<Integer>> argumentDependencies = new LinkedHashMap<>();
                for (int index = 0; index < call.getArguments().size(); index++) {
                    argumentDependencies.put(index, expressionDependencies(call.getArgument(index), dependencies));
                }

                List<CodeGraphIntegrationService.ScopedRelation> matches = byCaller
                        .getOrDefault(caller.symbol.getChunkId(), List.of()).stream()
                        .filter(relation -> call.getNameAsString().equals(relation.calledName()))
                        .toList();
                long sameNameCalls = calls.stream()
                        .filter(candidate -> candidate.getNameAsString().equals(call.getNameAsString())).count();
                // 多个同名调用或多个同名目标无法由局部现场唯一确认，必须继续保持候选状态。
                if (!matches.isEmpty() && (sameNameCalls != 1 || matches.size() != 1)) continue;
                boolean verified = false;
                for (CodeGraphIntegrationService.ScopedRelation relation : matches) {
                    MethodModel target = program.byChunkId.get(relation.calleeChunkId());
                    if (target == null) continue;
                    String key = relation.callerChunkId() + "->" + relation.calleeChunkId();
                    if (!verifiedRelations.add(key)) continue;
                    SemanticCallEdge edge = edge(taskId, caller.symbol, target.symbol, line(call),
                            call.getNameAsString(), call.toString(), "CODEGRAPH_VERIFIED", Confidence.MEDIUM,
                            "CodeGraph 拓扑已由调用方唯一局部 AST 调用现场独立验证", mapping(argumentDependencies));
                    program.edges.add(new GraphEdge(edge, caller, target, argumentDependencies));
                    program.exactResolvedCallSites++;
                    verified = true;
                }
                if (verified) continue;

                // 未命中作用域关系时只识别当前调用现场的数据库或安全框架边界。
                String scopeType = inferScopeType(call, caller, variableTypes);
                FrameworkModel framework = frameworkTarget(taskId, call, caller, scopeType, program);
                if (framework != null) {
                    SemanticCallEdge edge = edge(taskId, caller.symbol, framework.symbol, line(call),
                            call.getNameAsString(), call.toString(), framework.edgeType, framework.confidence,
                            framework.reason, mapping(argumentDependencies));
                    program.edges.add(new GraphEdge(edge, caller, framework, argumentDependencies));
                    program.frameworkResolvedCallSites++;
                } else {
                    // 保留局部未解析调用作为覆盖诊断，但它不能扩展作用域或进入安全证据路径。
                    SemanticCallEdge edge = edge(taskId, caller.symbol, null, line(call), call.getNameAsString(),
                            call.toString(), "LOCAL_UNRESOLVED", Confidence.LOW,
                            "当前作用域的 CodeGraph 关系中没有该调用，局部 AST 不猜测跨文件目标",
                            mapping(argumentDependencies));
                    program.edges.add(new GraphEdge(edge, caller, null, argumentDependencies));
                    program.unresolvedCallSites++;
                }
            }
        }

        // CodeGraph 返回但调用现场无法独立确认的关系保留为候选，不能成为安全流出边。
        for (CodeGraphIntegrationService.ScopedRelation relation : scopedRelations) {
            String key = relation.callerChunkId() + "->" + relation.calleeChunkId();
            if (verifiedRelations.contains(key)) continue;
            MethodModel caller = program.byChunkId.get(relation.callerChunkId());
            MethodModel target = program.byChunkId.get(relation.calleeChunkId());
            if (caller == null || target == null) continue;
            SemanticCallEdge edge = edge(taskId, caller.symbol, target.symbol, relation.reportedLine(),
                    relation.calledName(), "CodeGraph candidate " + key, "CODEGRAPH_CANDIDATE", Confidence.LOW,
                    "CodeGraph 返回关系，但调用方局部 AST 未找到唯一调用现场", "");
            program.edges.add(new GraphEdge(edge, caller, target, Map.of()));
        }
    }

    // 执行 LightweightSemanticAnalyzer 中的 typesCompatible 处理。
    private boolean typesCompatible(String actual, String expected) {
        String left = simpleType(actual).toLowerCase(Locale.ROOT);
        String right = simpleType(expected).toLowerCase(Locale.ROOT);
        if (left.equals(right)) return true;
        Set<String> numbers = Set.of("byte", "short", "int", "integer", "long", "float", "double", "bigdecimal");
        return numbers.contains(left) && numbers.contains(right)
                || left.equals("string") && (right.equals("charsequence") || right.equals("object"));
    }

    // 执行 LightweightSemanticAnalyzer 中的 frameworkTarget 处理。
    private FrameworkModel frameworkTarget(UUID taskId, MethodCallExpr call, MethodModel caller,
                                           String scopeType, Program program) {
        // 当项目内方法无法解析时，根据接收者类型和调用名称识别持久化 API 或安全 Guard 边界。
        String name = lower(call.getNameAsString());
        String owner = lower(scopeType);
        String expression = lower(call.toString());
        String edgeType;
        String kind;
        Confidence confidence;
        String reason;
        if ((owner.endsWith("repository") || owner.endsWith("mapper")
                || containsAny(owner, "jdbctemplate", "entitymanager", "sqlsession", "dslcontext"))
                && (name.matches("(?:find|get|read|query|select|count|exists|save|insert|update|delete|remove).*"))) {
            edgeType = owner.endsWith("mapper") ? "MYBATIS_MAPPER_API" : "PERSISTENCE_API";
            kind = "FRAMEWORK_SINK";
            confidence = Confidence.HIGH;
            reason = "根据接收者类型和数据访问方法识别框架持久层边界";
        } else if (containsAny(owner + " " + expression, "statement", "jdbctemplate", "entitymanager", "createquery",
                "createnativequery", "executequery", "executeupdate")) {
            edgeType = "DATABASE_API";
            kind = "FRAMEWORK_SINK";
            confidence = Confidence.HIGH;
            reason = "识别 JDBC/JPA 数据库调用边界";
        } else if (isSecurityGuardCall(name, expression)) {
            edgeType = "SECURITY_GUARD";
            kind = "SECURITY_GUARD";
            confidence = Confidence.MEDIUM;
            reason = "根据安全框架或自定义权限检查方法识别 Guard";
        } else {
            return null;
        }
        // 框架调用没有项目内方法声明，因此创建合成符号作为数据流可到达的终点或 Guard 节点。
        SemanticSymbol symbol = new SemanticSymbol(taskId, caller.symbol.getChunkId(), kind,
                (scopeType == null || scopeType.isBlank() ? caller.owner.qualifiedName : scopeType)
                        + "." + call.getNameAsString() + "@" + line(call),
                call.getNameAsString(), scopeType == null ? "Framework" : scopeType,
                call.toString(), "unknown", "", caller.symbol.getFilePath(), line(call), line(call),
                null, "", truncate(call.toString(), 12_000));
        FrameworkModel model = new FrameworkModel(symbol, edgeType, confidence, reason);
        program.symbols.add(symbol);
        program.frameworkNodes.add(model);
        return model;
    }

    // 判断是否满足 isSecurityGuardCall 对应的条件。
    private boolean isSecurityGuardCall(String name, String expression) {
        return containsAny(name + " " + expression, "checkpermission", "checkrole", "haspermission", "hasrole",
                "hasauthority", "checklogin", "checkowner", "checktenant", "isallowed", "authorize",
                "stputil.check", "subject.checkpermission", "subject.hasrole");
    }

    // 将 Spring 事件发布者与类型匹配的监听器补成显式跨方法调用边。
    private void addSpringEventEdges(UUID taskId, Program program) {
        // 监听器必须带事件监听注解且至少有一个参数，第一个参数代表接收的事件类型。
        List<MethodModel> listeners = program.methods.stream()
                .filter(method -> containsAny(lower(method.symbol.getAnnotations()),
                        "@eventlistener", "@transactionaleventlistener"))
                .filter(method -> !method.parameterTypes.isEmpty()).toList();
        if (listeners.isEmpty()) return;
        for (MethodModel publisher : program.methods) {
            // 发布方法内的局部变量类型和依赖关系用于识别事件对象及其污点来源。
            Map<String, String> variableTypes = variableTypes(publisher);
            for (MethodCallExpr call : publisher.declaration.findAll(MethodCallExpr.class)) {
                if (!call.getNameAsString().equals("publishEvent") || call.getArguments().isEmpty()) continue;
                // 只有发布参数类型与监听器首参数兼容时才建立 SPRING_EVENT 边。
                String eventType = inferExpressionType(call.getArgument(0), variableTypes);
                if (eventType.isBlank()) continue;
                Map<String, Set<Integer>> dependencies = variableDependencies(publisher, call);
                Set<Integer> eventDependencies = expressionDependencies(call.getArgument(0), dependencies);
                boolean linked = false;
                for (MethodModel listener : listeners) {
                    if (!typesCompatible(eventType, listener.parameterTypes.get(0))) continue;
                    Map<Integer, Set<Integer>> mapping = Map.of(0, eventDependencies);
                    SemanticCallEdge edge = edge(taskId, publisher.symbol, listener.symbol, line(call),
                            "publishEvent", call.toString(), "SPRING_EVENT", Confidence.HIGH,
                            "ApplicationEvent 类型与 @EventListener 参数精确匹配", mapping(mapping));
                    program.edges.add(new GraphEdge(edge, publisher, listener, mapping));
                    linked = true;
                }
                if (linked) {
                    // 成功补充框架边后移除同一调用点原先的 UNRESOLVED 占位边并修正覆盖率。
                    boolean removed = program.edges.removeIf(edge -> edge.caller == publisher
                            && edge.persisted.getCallSiteLine() == line(call)
                            && edge.persisted.getCalledName().equals("publishEvent")
                            && ("UNRESOLVED".equals(edge.persisted.getEdgeType())
                            || "LOCAL_UNRESOLVED".equals(edge.persisted.getEdgeType())));
                    if (removed) {
                        program.unresolvedCallSites = Math.max(0, program.unresolvedCallSites - 1);
                        program.frameworkResolvedCallSites++;
                    }
                }
            }
        }
    }

    // 按 namespace 与 statement id 连接 Mapper 方法和 MyBatis XML SQL。
    private void addMyBatisEdges(UUID taskId, Program program) {
        // Mapper 所属完整类名必须等于 XML namespace，方法名必须等于 statement id。
        for (SqlModel sql : program.sqlStatements) {
            for (MethodModel mapperMethod : program.methods) {
                if (!mapperMethod.owner.qualifiedName.equals(sql.namespace)
                        || !mapperMethod.symbol.getSimpleName().equals(sql.statementId)) continue;
                Map<Integer, Set<Integer>> identity = new LinkedHashMap<>();
                // Mapper 方法参数按相同序号进入 XML SQL，使用恒等映射继续传播污点。
                for (int index = 0; index < mapperMethod.parameterNames.size(); index++) {
                    identity.put(index, Set.of(index));
                }
                SemanticCallEdge edge = edge(taskId, mapperMethod.symbol, sql.symbol,
                        mapperMethod.symbol.getStartLine(), sql.statementId, sql.symbol.getDetails(),
                        "MYBATIS_XML", Confidence.HIGH, "MyBatis namespace 与 statement id 精确匹配", mapping(identity));
                program.edges.add(new GraphEdge(edge, mapperMethod, sql, identity));
            }
        }
    }

    // 通过共享持久化字段连接写入方法与原始 HTML 模板 Sink。
    private void addPersistenceEdges(UUID taskId, Program program) {
        // 先从包含常见保存操作的方法中识别可能写入数据库的文本字段。
        for (MethodModel writer : program.methods) {
            String source = lower(writer.symbol.getDetails());
            if (!containsAny(source, ".save(", "insert(", "updatebyid(", "persist(")) continue;
            Set<String> fields = PERSISTED_TEXT_FIELDS.stream().filter(source::contains).collect(Collectors.toSet());
            if (fields.isEmpty()) continue;
            for (ArtifactModel artifact : program.artifacts) {
                // 后端写入字段与模板原始输出字段同名时建立中可信持久化传播关系。
                String template = lower(artifact.symbol.getDetails());
                Set<String> shared = fields.stream().filter(template::contains).collect(Collectors.toSet());
                if (shared.isEmpty()) continue;
                SemanticCallEdge edge = edge(taskId, writer.symbol, artifact.symbol,
                        writer.symbol.getStartLine(), "persistent-render", String.join(",", shared),
                        "PERSISTENCE_FIELD", Confidence.MEDIUM,
                        "持久化写入字段与原始 HTML 输出字段关联: " + String.join(",", shared), "");
                program.edges.add(new GraphEdge(edge, writer, artifact, Map.of()));
            }
        }
    }

    // 汇总方法返回值、敏感副作用和安全控制，并沿调用边传播摘要。
    private void buildMethodSummaries(Program program) {
        // 第一轮只分析每个方法自身，不跨越方法边界。
        for (MethodModel method : program.methods) {
            MethodSummary summary = method.summary;
            // 记录返回表达式依赖的形参编号，便于判断调用返回值是否仍携带外部输入。
            for (ReturnStmt statement : method.declaration.findAll(ReturnStmt.class)) {
                if (statement.getExpression().isEmpty()) continue;
                Map<String, Set<Integer>> variables = variableDependencies(method, statement);
                summary.returnFromParameters.addAll(expressionDependencies(statement.getExpression().get(), variables));
            }
            // 识别每个调用造成的 SQL、数据访问、修改和资金操作副作用及其参数来源。
            Map<String, String> types = variableTypes(method);
            for (MethodCallExpr call : method.declaration.findAll(MethodCallExpr.class)) {
                Map<String, Set<Integer>> variables = variableDependencies(method, call);
                Set<Integer> affected = new LinkedHashSet<>();
                call.getArguments().forEach(argument -> affected.addAll(expressionDependencies(argument, variables)));
                String effect = effectKind(call, inferScopeType(call, method, types));
                if (effect != null) summary.mergeEffect(effect, affected);
                // 命中权限、角色、归属或租户检查方法时，将方法标记为包含安全 Guard。
                if (isSecurityGuardCall(lower(call.getNameAsString()), lower(call.toString()))) {
                    summary.guards.add(call.getNameAsString());
                }
            }
            // 类或方法上的权限注解也作为 Guard 摘要，但后续仍结合安全框架和全局策略判断。
            if (hasAuthorizationAnnotation(method.symbol.getAnnotations())) {
                summary.guards.add("权限注解");
            }
        }

        // 使用已解析调用边传播“参数会到达哪类敏感操作”的摘要；最多五轮即可覆盖常见分层项目。
        for (int iteration = 0; iteration < 5; iteration++) {
            boolean changed = false;
            for (GraphEdge edge : program.edges) {
                // 只有目标为项目内 Java 方法时才存在可向调用方传播的方法摘要。
                if (!(edge.target instanceof MethodModel target)
                        || edge.persisted.getConfidence() == Confidence.LOW
                        || "CODEGRAPH_CANDIDATE".equals(edge.persisted.getEdgeType())) continue;
                for (Map.Entry<String, Set<Integer>> effect : target.summary.effects.entrySet()) {
                    // 将被调用方法的形参依赖通过调用边参数映射换算成调用方法的形参依赖。
                    Set<Integer> mapped = composeDependencies(effect.getValue(), edge.argumentDependencies);
                    changed |= edge.caller.summary.mergeEffect(effect.getKey(), mapped);
                }
            }
            // 本轮没有任何摘要变化说明达到稳定点，可以提前结束传播。
            if (!changed) break;
        }
        // 把摘要附加到符号详情中，使后续路径判定和 Agent 证据能够看到跨层副作用。
        for (MethodModel method : program.methods) {
            String summary = "\n[METHOD_SUMMARY] returnFrom=" + method.summary.returnFromParameters
                    + "; effects=" + method.summary.effects + "; guards=" + method.summary.guards;
            method.symbol.setDetails(truncate(method.symbol.getDetails() + summary, 12_000));
        }
    }

    // 执行 LightweightSemanticAnalyzer 中的 effectKind 处理。
    private String effectKind(MethodCallExpr call, String scopeType) {
        String value = lower(scopeType) + " " + lower(call.toString());
        String name = lower(call.getNameAsString());
        if (SQL_DANGER.matcher(value).find() || containsAny(value, "statement.execute", "createnativequery")) {
            return "SQL";
        }
        if ((lower(scopeType).endsWith("repository") || lower(scopeType).endsWith("mapper"))
                && name.matches("(?:find|get|read|query|select|count|exists|save|insert|update|delete|remove).*")) {
            if (name.matches("(?:find|get|read|select|delete|update).*byid.*")) return "DIRECT_OBJECT_ACCESS";
            if (name.matches("(?:save|insert|update|delete|remove).*")) return "MUTATION";
            return "DATA_ACCESS";
        }
        if (containsAny(name, "delete", "update", "save", "insert", "approve", "disable")) return "MUTATION";
        return null;
    }

    // 执行 LightweightSemanticAnalyzer 中的 composeDependencies 处理。
    private Set<Integer> composeDependencies(Set<Integer> targetParameters,
                                             Map<Integer, Set<Integer>> argumentDependencies) {
        Set<Integer> result = new LinkedHashSet<>();
        for (Integer parameter : targetParameters) {
            result.addAll(argumentDependencies.getOrDefault(parameter, Set.of()));
        }
        return result;
    }

    // 从每个 HTTP 入口做有深度和状态预算的广度优先污点路径搜索。
    private List<SecurityFlow> buildSecurityFlows(UUID taskId, Program program, List<SecurityPolicy> policies) {
        // key 用于按入口、漏洞类型和授权维度去重，value 保存当前最优路径候选。
        Map<String, SecurityFlowCandidate> best = new LinkedHashMap<>();
        // 只有带 endpoint 的 Java 方法被视为外部请求能够直接进入的 Source。
        for (MethodModel entry : program.methods.stream().filter(method -> method.symbol.getEndpoint() != null).toList()) {
            // 接口所有形参初始都视为潜在不可信输入，并用参数序号表示污点集合。
            Set<Integer> initialTaint = new LinkedHashSet<>();
            for (int index = 0; index < entry.parameterNames.size(); index++) initialTaint.add(index);
            // PathState 同时携带当前节点、当前节点污点参数、经过的节点和经过的调用边。
            Deque<PathState> queue = new ArrayDeque<>();
            queue.add(new PathState(entry, initialTaint, List.of(entry), List.of()));
            int visited = 0;
            // 广度优先遍历优先检查较短路径，并由 maxStatesPerEntry 防止分支爆炸。
            while (!queue.isEmpty() && visited++ < Math.max(50, properties.getMaxStatesPerEntry())) {
                PathState state = queue.removeFirst();
                // 每到达一个节点就结合当前污点、路径内容和 Guard 判断是否形成风险线索。
                evaluateRisks(taskId, entry, state, program, policies, best);
                // 达到最大调用深度后仍评估当前节点，但不再继续扩展下一层。
                if (state.edges.size() >= Math.max(1, properties.getMaxCallDepth())) continue;
                for (GraphEdge edge : program.outgoing.getOrDefault(state.current.symbol().getId(), List.of())) {
                    // 无目标边不能继续遍历，同一路径重复节点会形成环，因此两者都跳过。
                    if (edge.target == null || state.nodes.stream().anyMatch(node -> node.symbol().getId().equals(edge.target.symbol().getId()))) {
                        continue;
                    }
                    // 根据实参到形参映射，把当前节点的污点参数转换成下一节点的污点参数。
                    Set<Integer> nextTaint = propagateTaint(state.taintedParameters, edge.argumentDependencies);
                    List<ProgramNode> nextNodes = append(state.nodes, edge.target);
                    List<GraphEdge> nextEdges = append(state.edges, edge);
                    queue.addLast(new PathState(edge.target, nextTaint, nextNodes, nextEdges));
                }
            }
        }
        // 对没有后端写入关系但自身存在原始 HTML 输出的模板补充低可信 XSS 线索。
        addStandaloneTemplateFlows(taskId, program, best);
        // 输出前只保留 SecurityFlow 实体，并按漏洞枚举排序以保证结果稳定。
        return best.values().stream().map(SecurityFlowCandidate::flow)
                .sorted(Comparator.comparing(flow -> flow.getType().name())).toList();
    }

    // 在当前路径上检查七类风险的 Source、Sink 与缺失 Guard 组合。
    private void evaluateRisks(UUID taskId, MethodModel entry, PathState state, Program program,
                               List<SecurityPolicy> policies, Map<String, SecurityFlowCandidate> best) {
        String current = lower(state.current.symbol().getDetails());
        String path = state.nodes.stream().map(node -> lower(node.symbol().getDetails())).collect(Collectors.joining("\n"));
        String entryText = lower(entry.symbol.getEndpoint() + " " + entry.symbol.getSimpleName() + " "
                + entry.symbol.getParameterTypes() + " " + entry.symbol.getAnnotations());
        MethodSummary summary = state.current instanceof MethodModel method ? method.summary : MethodSummary.empty();

        // SQL 注入线索要求污点到达动态 SQL 或原始执行点，并且当前路径未确认参数化查询保护。
        if ((SQL_DANGER.matcher(current).find() || summary.taintedEffect("SQL", state.taintedParameters))
                && (!state.taintedParameters.isEmpty() || current.contains("${"))
                && !containsAny(current, "preparestatement", "namedparameterjdbctemplate")) {
            offer(taskId, VulnerabilityType.SQL_INJECTION, entry, state,
                    "HTTP 参数 " + entry.parameterNames, "动态 SQL 或原始 SQL 执行",
                    "参数化查询/结构白名单：当前路径未确认", program, best);
        }

        // 水平越权线索要求接口存在资源 ID、路径到达按 ID 数据访问且未发现归属或租户 Guard。
        boolean resourceId = containsAny(entryText + " " + lower(entry.symbol.getDetails()),
                "{id}", "orderid", "userid", "accountid", "resourceid", " id");
        boolean dataAccessNode = state.current.symbol().getKind().equals("MYBATIS_SQL")
                || state.current.symbol().getKind().equals("FRAMEWORK_SINK")
                || lower(state.current.symbol().getOwnerName()).endsWith("mapper")
                || lower(state.current.symbol().getOwnerName()).endsWith("repository")
                || summary.hasEffect("DATA_ACCESS") || summary.hasEffect("DIRECT_OBJECT_ACCESS")
                || containsAny(current, "mapper.", "repository.", "jdbctemplate", "entitymanager");
        boolean directObjectAccess = dataAccessNode && containsAny(current, "getbyid(", "selectbyid(", "findbyid(",
                "deletebyid(", "updatebyid(", " where id", "where id")
                || summary.hasEffect("DIRECT_OBJECT_ACCESS");
        boolean ownershipGuard = containsAny(path, "currentuserid", "loginuserid", "getcurrentuser",
                "checkowner", "owner_id", "ownerid ==", "ownerid.equals", "tenant_id", "tenantid",
                "datascope", "@datascope", "checktenant");
        if (resourceId && directObjectAccess && !ownershipGuard) {
            offer(taskId, VulnerabilityType.AUTHORIZATION, entry, state,
                    "接口资源标识参数", "按资源 ID 查询、修改或删除",
                    "资源归属/租户约束：调用路径中未发现", program, best);
        }

        // 垂直越权线索要求敏感业务操作到达修改或特权 Sink 且没有角色、权限或全局策略保护。
        boolean sensitiveOperation = containsAny(entryText + " " + current, "admin", "permission", "role",
                "refund", "withdraw", "export", "delete", "disable", "approve", "setbalance", "payment");
        boolean verticalGuard = hasAuthorizationGuard(path) || !summary.guards.isEmpty()
                || policyProtects(entry.symbol.getEndpoint(), policies, true);
        boolean privilegedSink = dataAccessNode && (isMutation(current) || summary.hasEffect("MUTATION"))
                || containsAny(current, "paymentgateway.", "refundgateway.", "bankclient.", "adminclient.");
        if (sensitiveOperation && !verticalGuard && privilegedSink) {
            offer(taskId, VulnerabilityType.AUTHORIZATION, entry, state,
                    "HTTP 敏感业务入口", "管理、审批、删除或资金操作",
                    "角色/权限限制：调用路径及匹配的 SecurityFilterChain 中未发现", program, best);
        }

        // 未授权泄露线索要求匿名或公开接口路径中出现密码、令牌、余额等敏感响应数据。
        boolean publicEndpoint = containsAny(entryText, "@permitall", "@anonymous", "/public/", "/open/", "/anonymous/")
                || policyPermits(entry.symbol.getEndpoint(), policies);
        boolean sensitiveData = containsAny(current, "password", "secret", "apikey", "privatekey",
                "idcard", "bankcard", "balance", "token", "salary");
        if (publicEndpoint && sensitiveData) {
            offer(taskId, VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE, entry, state,
                    "允许匿名访问的接口", "敏感字段进入接口返回路径",
                    "认证要求/响应字段白名单：未确认", program, best);
        }

        // 存储型 XSS 线索要求持久化文本到达原始 HTML Sink 且路径中未发现白名单清洗或编码。
        if (state.current.symbol().getKind().equals("TEMPLATE_SINK") && RAW_HTML.matcher(current).find()
                && !containsAny(path, "sanitize", "encodeforhtml", "htmlclean", "jsoup.clean")) {
            offer(taskId, VulnerabilityType.STORED_XSS, entry, state,
                    "用户可控持久化文本", "持久化字段进入原始 HTML 渲染",
                    "HTML 白名单清洗/上下文编码：路径中未发现", program, best);
        }

        // 验证绕过线索根据验证码、签名或审批流程中的异常控制流模式生成。
        boolean verificationFlow = containsAny(current, "verify", "captcha", "otp", "signature",
                "checkpassword", "approve", "validatestatus");
        if (verificationFlow && VALIDATION_BYPASS.matcher(current).find()) {
            offer(taskId, VulnerabilityType.VALIDATION_BYPASS, entry, state,
                    "客户端标志或验证结果", "验证失败后仍可到达敏感操作",
                    "失败即终止控制流：未确认", program, best);
        }

    }

    // 将风险路径固化为调查线索，并按入口和风险维度保留最佳路径。
    private void offer(UUID taskId, VulnerabilityType type, MethodModel entry, PathState state,
                       String source, String sink, String guard, Program program,
                       Map<String, SecurityFlowCandidate> best) {
        // 安全流只引用已关联 Recon Chunk 的节点，避免生成无法回到真实源码的证据路径。
        List<Long> chunkIds = state.nodes.stream().map(node -> node.symbol().getChunkId())
                .filter(Objects::nonNull).distinct().toList();
        if (chunkIds.isEmpty() || entry.symbol.getChunkId() == null) return;
        // 统计路径节点仍有多少未解析出边，用于表达语义覆盖缺口而不是隐瞒不确定性。
        Set<UUID> pathSymbolIds = state.nodes.stream()
                .map(node -> node.symbol().getId())
                .collect(Collectors.toSet());
        int unresolved = (int) program.edges.stream()
                .filter(edge -> pathSymbolIds.contains(edge.persisted.getCallerSymbolId()))
                .filter(edge -> "UNRESOLVED".equals(edge.persisted.getEdgeType())
                        || "LOCAL_UNRESOLVED".equals(edge.persisted.getEdgeType())
                        || "CODEGRAPH_CANDIDATE".equals(edge.persisted.getEdgeType()))
                .count();
        // 路径无未解析边且不含低可信边为高可信，少量缺口降为中可信，其余为低可信。
        boolean lowEdge = state.edges.stream().anyMatch(edge -> edge.persisted.getConfidence() == Confidence.LOW);
        Confidence confidence = unresolved == 0 && !lowEdge ? Confidence.HIGH
                : unresolved <= 2 ? Confidence.MEDIUM : Confidence.LOW;
        String pathText = formatPath(type, state, source, sink, guard, unresolved);
        // SecurityFlow 保存结构化 Source、Sink、Guard 以及 Agent 可引用的完整路径文本和 Chunk ID。
        SecurityFlow flow = new SecurityFlow(taskId, type, entry.symbol.getId(), state.current.symbol().getId(),
                entry.symbol.getChunkId(), source, sink, guard, pathText,
                chunkIds.stream().map(String::valueOf).collect(Collectors.joining(",")), confidence,
                state.edges.size(), unresolved);
        // 越权漏洞仍保留“资源归属”和“角色权限”两种证据路径，分类合并不应丢失调查维度。
        String dimension = type == VulnerabilityType.AUTHORIZATION ? "|" + source : "";
        String key = entry.symbol.getId() + "|" + type + dimension;
        SecurityFlowCandidate candidate = new SecurityFlowCandidate(flow, state.edges.size());
        SecurityFlowCandidate previous = best.get(key);
        if (previous == null) {
            // 每个入口最多保存 maxPathsPerEntry 条风险路径，限制大型调用图的结果规模。
            long entryPaths = best.keySet().stream()
                    .filter(item -> item.startsWith(entry.symbol.getId() + "|")).count();
            if (entryPaths >= Math.max(1, properties.getMaxPathsPerEntry())) return;
        }
        // 相同入口和风险维度只保留覆盖调用链更长的路径，为 Agent 提供更完整上下文。
        if (previous == null || candidate.pathLength > previous.pathLength) best.put(key, candidate);
    }

    // 为无法解析写入来源的独立原始 HTML 模板保留低可信调查线索。
    private void addStandaloneTemplateFlows(UUID taskId, Program program,
                                            Map<String, SecurityFlowCandidate> best) {
        for (ArtifactModel artifact : program.artifacts) {
            boolean referenced = program.edges.stream().anyMatch(edge -> edge.target != null
                    && edge.target.symbol().getId().equals(artifact.symbol.getId()));
            if (referenced || artifact.symbol.getChunkId() == null) continue;
            String guard = "持久化写入来源未解析；HTML 白名单清洗/上下文编码：当前模板中未发现";
            String path = "[UNRESOLVED_SOURCE] 未找到持久化写入方法\n[SINK] "
                    + location(artifact.symbol) + " 原始 HTML 渲染\n[GUARD] " + guard
                    + "\n[COVERAGE] 已解析调用边=0，未解析边=1";
            SecurityFlow flow = new SecurityFlow(taskId, VulnerabilityType.STORED_XSS, null,
                    artifact.symbol.getId(), artifact.symbol.getChunkId(), "待追踪的持久化文本",
                    "原始 HTML 渲染", guard, path, String.valueOf(artifact.symbol.getChunkId()),
                    Confidence.LOW, 0, 1);
            best.putIfAbsent("template|" + artifact.symbol.getId(), new SecurityFlowCandidate(flow, 0));
        }
    }

    // 格式化并输出 formatPath 对应的展示内容。
    private String formatPath(VulnerabilityType type, PathState state, String source, String sink,
                              String guard, int unresolved) {
        // 统一格式化 TYPE、SOURCE、CALL、SINK、GUARD 和 COVERAGE，供工具结果与 Critic 直接读取。
        StringBuilder result = new StringBuilder();
        result.append("[TYPE] ").append(type).append('\n');
        result.append("[SOURCE] ").append(source).append(" @ ").append(location(state.nodes.get(0).symbol())).append('\n');
        for (int index = 0; index < state.edges.size(); index++) {
            GraphEdge edge = state.edges.get(index);
            result.append("[CALL ").append(index + 1).append("] ")
                    .append(location(edge.caller.symbol)).append(" -> ")
                    .append(location(edge.target.symbol())).append(" | ")
                    .append(edge.persisted.getEdgeType()).append(" | ")
                    .append(edge.persisted.getConfidence()).append(" | 参数流=")
                    .append(edge.persisted.getArgumentMapping()).append('\n');
        }
        result.append("[SINK] ").append(sink).append(" @ ").append(location(state.current.symbol())).append('\n');
        result.append("[GUARD] ").append(guard).append('\n');
        result.append("[COVERAGE] 已解析调用边=").append(state.edges.size())
                .append("，未解析边=").append(unresolved);
        return result.toString();
    }

    // 从 Spring Security 配置代码块中提取接口模式及授权动作。
    private List<SecurityPolicy> extractSecurityPolicies(List<CodeChunk> chunks) {
        List<SecurityPolicy> result = new ArrayList<>();
        // 在全部 Chunk 中查找 requestMatchers 等安全配置，而不是只检查当前接口文件。
        for (CodeChunk chunk : chunks) {
            Matcher matcher = SECURITY_POLICY.matcher(chunk.getContent());
            while (matcher.find()) {
                // 一个安全配置调用可能包含多个路径字符串，每个路径单独保存授权动作。
                Matcher paths = QUOTED.matcher(matcher.group(1));
                while (paths.find()) result.add(new SecurityPolicy(paths.group(1), matcher.group(2)));
            }
        }
        return result;
    }

    // 执行 LightweightSemanticAnalyzer 中的 policyProtects 处理。
    private boolean policyProtects(String endpoint, List<SecurityPolicy> policies, boolean requireRole) {
        return policies.stream().filter(policy -> endpointMatches(endpoint, policy.pattern))
                .anyMatch(policy -> !policy.action.equalsIgnoreCase("permitAll")
                        && (!requireRole || policy.action.toLowerCase(Locale.ROOT).startsWith("has")));
    }

    // 执行 LightweightSemanticAnalyzer 中的 policyPermits 处理。
    private boolean policyPermits(String endpoint, List<SecurityPolicy> policies) {
        return policies.stream().anyMatch(policy -> endpointMatches(endpoint, policy.pattern)
                && policy.action.equalsIgnoreCase("permitAll"));
    }

    // 判断是否满足 hasAuthorizationGuard 对应的条件。
    private boolean hasAuthorizationGuard(String path) {
        return containsAny(path, "@preauthorize", "@postauthorize", "@secured", "@rolesallowed",
                "@requirespermissions", "@requiresroles", "@sacheckpermission", "@sacheckrole",
                "hasrole", "hasauthority", "checkpermission", "checkrole", "checklogin",
                "stputil.check", "subject.checkpermission") || hasAuthorizationAnnotation(path);
    }

    // 判断是否满足 hasAuthorizationAnnotation 对应的条件。
    private boolean hasAuthorizationAnnotation(String value) {
        if (value == null) return false;
        Matcher matcher = Pattern.compile("@([A-Za-z_$][\\w$]*)").matcher(value);
        while (matcher.find()) {
            String name = matcher.group(1).toLowerCase(Locale.ROOT);
            if (containsAny(name, "authorize", "permission", "accesscontrol", "datascope", "checkrole",
                    "requiresrole", "sacheck", "tenantguard")) return true;
        }
        return false;
    }

    // 执行 LightweightSemanticAnalyzer 中的 endpointMatches 处理。
    private boolean endpointMatches(String endpoint, String antPattern) {
        if (endpoint == null || antPattern == null) return false;
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
                    regex.append(Pattern.quote(String.valueOf(current)));
                }
            } else {
                regex.append(Pattern.quote(String.valueOf(current)));
            }
        }
        return endpoint.matches(regex.append('$').toString());
    }

    // 执行 LightweightSemanticAnalyzer 中的 variableTypes 处理。
    private Map<String, String> variableTypes(MethodModel method) {
        // 建立字段、形参和局部变量名到简单类型名的映射，为调用目标启发式解析提供接收者类型。
        Map<String, String> result = new LinkedHashMap<>();
        for (FieldDeclaration field : method.owner.declaration.getFields()) {
            field.getVariables().forEach(variable -> result.put(variable.getNameAsString(), resolvedVariableType(variable)));
        }
        method.declaration.getParameters().forEach(parameter -> {
            String type;
            try { type = simpleType(parameter.getType().resolve().describe()); }
            catch (RuntimeException exception) { type = simpleType(parameter.getTypeAsString()); }
            result.put(parameter.getNameAsString(), type);
        });
        method.declaration.findAll(VariableDeclarator.class).forEach(variable ->
                result.put(variable.getNameAsString(), resolvedVariableType(variable)));
        return result;
    }

    // 解析并确定 resolvedVariableType 对应的目标。
    private String resolvedVariableType(VariableDeclarator variable) {
        // var 声明优先根据初始化表达式推断类型，其他变量优先符号求解并在失败时使用源码类型。
        if (variable.getTypeAsString().equals("var") && variable.getInitializer().isPresent()) {
            String inferred = inferExpressionType(variable.getInitializer().get(), Map.of());
            if (!inferred.isBlank()) return inferred;
        }
        try { return simpleType(variable.getType().resolve().describe()); }
        catch (RuntimeException exception) { return simpleType(variable.getTypeAsString()); }
    }

    // 执行 LightweightSemanticAnalyzer 中的 variableDependencies 处理。
    private Map<String, Set<Integer>> variableDependencies(MethodModel method, Node before) {
        // 依赖集合中的整数表示当前方法形参序号，例如变量依赖 {0,2} 表示来源于第 0、2 个形参。
        Map<String, Set<Integer>> result = new LinkedHashMap<>();
        // 每个形参初始只依赖自身，是局部污点传播的起点。
        for (int index = 0; index < method.parameterNames.size(); index++) {
            result.put(method.parameterNames.get(index), Set.of(index));
        }
        List<Node> assignments = new ArrayList<>();
        assignments.addAll(method.declaration.findAll(VariableDeclarator.class));
        assignments.addAll(method.declaration.findAll(AssignExpr.class));
        assignments.addAll(method.declaration.findAll(MethodCallExpr.class).stream()
                .filter(call -> call.getNameAsString().startsWith("set") && call.getScope().isPresent())
                .toList());
        // 按源码顺序只处理目标调用点之前的赋值，避免使用尚未发生的后续状态。
        assignments.sort(Comparator.comparingInt(this::line).thenComparingInt(this::column));
        for (Node node : assignments) {
            if (line(node) > line(before) || (line(node) == line(before) && column(node) >= column(before))) break;
            if (node instanceof VariableDeclarator variable && variable.getInitializer().isPresent()) {
                // 局部变量继承其初始化表达式中所有变量的形参依赖。
                result.put(variable.getNameAsString(), expressionDependencies(variable.getInitializer().get(), result));
            } else if (node instanceof AssignExpr assignment) {
                // 普通赋值用右值依赖覆盖目标变量的当前依赖。
                String target = assignedName(assignment.getTarget());
                if (target != null) result.put(target, expressionDependencies(assignment.getValue(), result));
            } else if (node instanceof MethodCallExpr setter && setter.getScope().get() instanceof NameExpr object) {
                // setter 调用把对象原有依赖与 setter 实参依赖合并，近似表示字段被外部输入污染。
                Set<Integer> dependencies = new LinkedHashSet<>(result.getOrDefault(object.getNameAsString(), Set.of()));
                setter.getArguments().forEach(argument -> dependencies.addAll(expressionDependencies(argument, result)));
                result.put(object.getNameAsString(), Set.copyOf(dependencies));
            }
        }
        return result;
    }

    // 执行 LightweightSemanticAnalyzer 中的 expressionDependencies 处理。
    private Set<Integer> expressionDependencies(Expression expression, Map<String, Set<Integer>> variables) {
        // 收集表达式自身及其所有子表达式中的变量引用，并合并这些变量对应的形参来源。
        Set<Integer> result = new LinkedHashSet<>();
        if (expression instanceof NameExpr name) result.addAll(variables.getOrDefault(name.getNameAsString(), Set.of()));
        expression.findAll(NameExpr.class).forEach(name -> result.addAll(variables.getOrDefault(name.getNameAsString(), Set.of())));
        return Set.copyOf(result);
    }

    // 执行 LightweightSemanticAnalyzer 中的 inferScopeType 处理。
    private String inferScopeType(MethodCallExpr call, MethodModel caller, Map<String, String> variables) {
        // 无显式接收者时使用当前类，字段、变量和嵌套调用则依次尝试本地类型表与符号求解。
        if (call.getScope().isEmpty()) return caller.owner.simpleName;
        Expression scope = call.getScope().get();
        if (scope instanceof NameExpr name) return variables.getOrDefault(name.getNameAsString(), name.getNameAsString());
        if (scope instanceof FieldAccessExpr field) return variables.get(field.getNameAsString());
        if (scope instanceof MethodCallExpr nested) {
            try { return simpleType(nested.resolve().getReturnType().describe()); }
            catch (RuntimeException ignored) { }
        }
        try { return simpleType(scope.calculateResolvedType().describe()); }
        catch (RuntimeException ignored) { }
        return null;
    }

    // 执行 LightweightSemanticAnalyzer 中的 inferExpressionType 处理。
    private String inferExpressionType(Expression expression, Map<String, String> variables) {
        // 优先处理常见字面量和对象创建表达式，复杂表达式再交给 JavaParser 类型求解。
        if (expression instanceof NameExpr name) return variables.getOrDefault(name.getNameAsString(), "");
        if (expression instanceof ObjectCreationExpr creation) return simpleType(creation.getTypeAsString());
        if (expression.isStringLiteralExpr()) return "String";
        if (expression.isIntegerLiteralExpr()) return "int";
        if (expression.isLongLiteralExpr()) return "long";
        if (expression.isDoubleLiteralExpr()) return "double";
        if (expression.isBooleanLiteralExpr()) return "boolean";
        try { return simpleType(expression.calculateResolvedType().describe()); }
        catch (RuntimeException exception) { return ""; }
    }

    // 执行 LightweightSemanticAnalyzer 中的 propagateTaint 处理。
    private Set<Integer> propagateTaint(Set<Integer> current, Map<Integer, Set<Integer>> argumentDependencies) {
        // 某个实参依赖当前污点参数时，对应的被调用方法形参序号成为下一节点污点。
        Set<Integer> result = new LinkedHashSet<>();
        for (Map.Entry<Integer, Set<Integer>> argument : argumentDependencies.entrySet()) {
            if (argument.getValue().stream().anyMatch(current::contains)) result.add(argument.getKey());
        }
        return Set.copyOf(result);
    }

    // 执行 LightweightSemanticAnalyzer 中的 edge 处理。
    private SemanticCallEdge edge(UUID taskId, SemanticSymbol caller, SemanticSymbol callee, int line,
                                  String name, String expression, String type, Confidence confidence,
                                  String reason, String argumentMapping) {
        // 将内存解析结果统一转换成带 Chunk、定位、可信度和参数映射的持久化调用边。
        return new SemanticCallEdge(taskId, caller.getId(), callee == null ? null : callee.getId(),
                caller.getChunkId(), callee == null ? null : callee.getChunkId(), line, name,
                truncate(expression, 4_000), type, confidence, reason, argumentMapping);
    }

    // 转换并返回 mapping 对应的数据表示。
    private String mapping(Map<Integer, Set<Integer>> dependencies) {
        return dependencies.entrySet().stream().filter(entry -> !entry.getValue().isEmpty())
                .map(entry -> entry.getKey() + "<-" + entry.getValue().stream().map(String::valueOf)
                        .collect(Collectors.joining("+")))
                .collect(Collectors.joining(";"));
    }

    // 解析并确定 resolvedSignature 对应的目标。
    private Optional<String> resolvedSignature(MethodDeclaration method) {
        try {
            return Optional.of(method.resolve().getQualifiedSignature());
        } catch (RuntimeException exception) {
            return Optional.empty();
        }
    }

    // 执行 LightweightSemanticAnalyzer 中的 fallbackSignature 处理。
    private String fallbackSignature(String owner, MethodDeclaration method) {
        return owner + "." + method.getNameAsString() + "(" + method.getParameters().stream()
                .map(parameter -> parameter.getTypeAsString()).collect(Collectors.joining(",")) + ")";
    }

    // 执行 LightweightSemanticAnalyzer 中的 fallbackOwner 处理。
    private String fallbackOwner(CompilationUnit unit, TypeDeclaration<?> declaration) {
        String packageName = unit.getPackageDeclaration().map(value -> value.getNameAsString() + ".").orElse("");
        List<String> owners = new ArrayList<>();
        Node current = declaration;
        while (current instanceof TypeDeclaration<?> type) {
            owners.add(0, type.getNameAsString());
            current = type.getParentNode().orElse(null);
        }
        return packageName + String.join(".", owners);
    }

    // 执行 LightweightSemanticAnalyzer 中的 assignedName 处理。
    private String assignedName(Expression target) {
        if (target instanceof NameExpr name) return name.getNameAsString();
        if (target instanceof FieldAccessExpr field) return field.getNameAsString();
        return null;
    }

    // 执行 LightweightSemanticAnalyzer 中的 simpleType 处理。
    private String simpleType(String type) {
        if (type == null) return "";
        String value = type.replaceAll("<.*>", "").replace("[]", "").strip();
        int dot = value.lastIndexOf('.');
        return dot < 0 ? value : value.substring(dot + 1);
    }

    // 判断是否满足 isMutation 对应的条件。
    private boolean isMutation(String content) {
        return containsAny(content, "delete", "update", "save", "insert", "refund", "withdraw", "approve", "disable", "setrole", "setpermission");
    }

    // 判断是否满足 containsAny 对应的条件。
    private boolean containsAny(String content, String... tokens) {
        if (content == null) return false;
        for (String token : tokens) if (content.contains(token.toLowerCase(Locale.ROOT))) return true;
        return false;
    }

    // 执行 LightweightSemanticAnalyzer 中的 lower 处理。
    private String lower(String value) { return value == null ? "" : value.toLowerCase(Locale.ROOT); }
    // 执行 LightweightSemanticAnalyzer 中的 line 处理。
    private int line(Node node) { return node.getBegin().map(position -> position.line).orElse(1); }
    // 执行 LightweightSemanticAnalyzer 中的 column 处理。
    private int column(Node node) { return node.getBegin().map(position -> position.column).orElse(1); }
    // 执行 LightweightSemanticAnalyzer 中的 endLine 处理。
    private int endLine(Node node) { return node.getEnd().map(position -> position.line).orElse(line(node)); }
    // 执行 LightweightSemanticAnalyzer 中的 countLines 处理。
    private int countLines(String value, int endExclusive) {
        return (int) value.substring(0, Math.min(value.length(), endExclusive)).chars().filter(character -> character == '\n').count();
    }
    // 规范化 normalized 对应的输入。
    private String normalized(Path path) { return path.toString().replace('\\', '/'); }
    // 执行 LightweightSemanticAnalyzer 中的 truncate 处理。
    private String truncate(String value, int max) { return value == null ? "" : value.substring(0, Math.min(max, value.length())); }
    // 执行 LightweightSemanticAnalyzer 中的 key 处理。
    // 执行 LightweightSemanticAnalyzer 中的 location 处理。
    private String location(SemanticSymbol symbol) {
        return symbol.getFilePath() + ":" + symbol.getStartLine() + " " + symbol.getQualifiedName()
                + (symbol.getChunkId() == null ? "" : " [CHUNK " + symbol.getChunkId() + "]");
    }

    // 向当前结果添加 append 对应的数据。
    private <T> List<T> append(List<T> source, T item) {
        List<T> result = new ArrayList<>(source);
        result.add(item);
        return List.copyOf(result);
    }

    // 封装 Result 使用的不可变结构化数据。
    public record Result(List<SemanticSymbol> symbols, List<SemanticCallEdge> edges,
                         List<SecurityFlow> flows, CallGraphCoverage coverage) {}

    // 封装 CallGraphCoverage 使用的不可变结构化数据。
    public record CallGraphCoverage(int totalCallSites, int exactResolvedCallSites,
                                    int heuristicResolvedCallSites, int frameworkResolvedCallSites,
                                    int externalCallSites, int unresolvedCallSites) {
        // 执行 CallGraphCoverage 中的 internalResolutionRate 处理。
        public double internalResolutionRate() {
            int internal = exactResolvedCallSites + heuristicResolvedCallSites
                    + frameworkResolvedCallSites + unresolvedCallSites;
            return internal == 0 ? 1.0
                    : (double) (exactResolvedCallSites + heuristicResolvedCallSites + frameworkResolvedCallSites) / internal;
        }
    }

    // 定义 ProgramNode 的协作接口和能力边界。
    private interface ProgramNode {
        // 返回当前程序节点对应的语义符号。
        SemanticSymbol symbol();
    }

    // 封装 Program 相关的数据与处理逻辑。
    private static final class Program {
        private final Path root;
        private final List<CodeChunk> chunks;
        private final List<SemanticSymbol> symbols = new ArrayList<>();
        private final List<MethodModel> methods = new ArrayList<>();
        private final List<SqlModel> sqlStatements = new ArrayList<>();
        private final List<ArtifactModel> artifacts = new ArrayList<>();
        private final List<FrameworkModel> frameworkNodes = new ArrayList<>();
        private final List<GraphEdge> edges = new ArrayList<>();
        private final Map<String, TypeModel> types = new LinkedHashMap<>();
        private final Map<Long, MethodModel> byChunkId = new HashMap<>();
        private final Map<UUID, List<GraphEdge>> outgoing = new HashMap<>();
        private int totalCallSites;
        private int exactResolvedCallSites;
        private int heuristicResolvedCallSites;
        private int frameworkResolvedCallSites;
        private int externalCallSites;
        private int unresolvedCallSites;

        // 创建 Program 实例并初始化所需依赖或状态。
        private Program(Path root, List<CodeChunk> chunks) { this.root = root; this.chunks = chunks; }

        // 查询并返回 findChunk 对应的数据。
        private CodeChunk findChunk(String file, int line, String type) {
            // 在同文件同类型且覆盖目标行的 Chunk 中，选择起始行距离最近的一块作为语义证据载体。
            return chunks.stream().filter(chunk -> chunk.getFilePath().equals(file))
                    .filter(chunk -> type.equals(chunk.getChunkType()))
                    .filter(chunk -> line >= chunk.getStartLine() && line <= chunk.getEndLine())
                    .min(Comparator.comparingInt(chunk -> Math.abs(chunk.getStartLine() - line))).orElse(null);
        }

        // 执行 Program 中的 index 处理。
        private void index() {
            methods.stream().filter(method -> method.symbol.getChunkId() != null)
                    .forEach(method -> byChunkId.put(method.symbol.getChunkId(), method));
        }

        // 构建并返回 buildOutgoing 对应的结果。
        private void buildOutgoing() {
            // 路径搜索按当前符号查询下一跳，因此将扁平边列表重建为调用方邻接表。
            outgoing.clear();
            for (GraphEdge edge : edges) {
                if (edge.target == null || edge.persisted.getConfidence() == Confidence.LOW
                        || "CODEGRAPH_CANDIDATE".equals(edge.persisted.getEdgeType())
                        || "LOCAL_UNRESOLVED".equals(edge.persisted.getEdgeType())) continue;
                outgoing.computeIfAbsent(edge.persisted.getCallerSymbolId(), ignored -> new ArrayList<>()).add(edge);
            }
        }

        // 执行 Program 中的 coverage 处理。
        private CallGraphCoverage coverage() {
            // 将构图期间累计的精确、启发式、框架、外部和未解析计数封装为覆盖率快照。
            return new CallGraphCoverage(totalCallSites, exactResolvedCallSites, heuristicResolvedCallSites,
                    frameworkResolvedCallSites, externalCallSites, unresolvedCallSites);
        }
    }

    // 封装 TypeModel 相关的数据与处理逻辑。
    private static final class TypeModel {
        private final String qualifiedName;
        private final String simpleName;
        private final TypeDeclaration<?> declaration;
        private final List<MethodModel> methods = new ArrayList<>();

        // 创建 TypeModel 实例并初始化所需依赖或状态。
        private TypeModel(String qualifiedName, String simpleName, TypeDeclaration<?> declaration) {
            this.qualifiedName = qualifiedName;
            this.simpleName = simpleName;
            this.declaration = declaration;
        }
    }

    // 封装 MethodModel 相关的数据与处理逻辑。
    private static final class MethodModel implements ProgramNode {
        private final SemanticSymbol symbol;
        private final MethodDeclaration declaration;
        private final TypeModel owner;
        private final List<String> parameterNames;
        private final List<String> parameterTypes;
        private final MethodSummary summary = new MethodSummary();

        // 创建 MethodModel 实例并初始化所需依赖或状态。
        private MethodModel(SemanticSymbol symbol, MethodDeclaration declaration, TypeModel owner,
                            List<String> parameterNames, List<String> parameterTypes) {
            this.symbol = symbol; this.declaration = declaration; this.owner = owner;
            this.parameterNames = parameterNames; this.parameterTypes = parameterTypes;
        }
        // 执行 MethodModel 中的 symbol 处理。
        // 返回 SQL 节点对应的语义符号。
        @Override public SemanticSymbol symbol() { return symbol; }
    }

    // 封装 SqlModel 相关的数据与处理逻辑。
    private static final class SqlModel implements ProgramNode {
        private final SemanticSymbol symbol;
        private final String namespace;
        private final String statementId;
        // 创建 SqlModel 实例并初始化所需依赖或状态。
        private SqlModel(SemanticSymbol symbol, String namespace, String statementId) {
            this.symbol = symbol; this.namespace = namespace; this.statementId = statementId;
        }
        // 返回静态资源节点对应的语义符号。
        @Override public SemanticSymbol symbol() { return symbol; }
    }

    // 封装 ArtifactModel 相关的数据与处理逻辑。
    private static final class ArtifactModel implements ProgramNode {
        private final SemanticSymbol symbol;
        // 创建 ArtifactModel 实例并初始化所需依赖或状态。
        private ArtifactModel(SemanticSymbol symbol) { this.symbol = symbol; }
        // 返回框架节点对应的语义符号。
        @Override public SemanticSymbol symbol() { return symbol; }
    }

    // 封装 FrameworkModel 相关的数据与处理逻辑。
    private static final class FrameworkModel implements ProgramNode {
        private final SemanticSymbol symbol;
        private final String edgeType;
        private final Confidence confidence;
        private final String reason;

        // 创建 FrameworkModel 实例并初始化所需依赖或状态。
        private FrameworkModel(SemanticSymbol symbol, String edgeType, Confidence confidence, String reason) {
            this.symbol = symbol; this.edgeType = edgeType; this.confidence = confidence; this.reason = reason;
        }
        // 返回框架节点对应的语义符号。
        @Override public SemanticSymbol symbol() { return symbol; }
    }

    // 封装 MethodSummary 相关的数据与处理逻辑。
    private static final class MethodSummary {
        private static final MethodSummary EMPTY = new MethodSummary();
        private final Set<Integer> returnFromParameters = new LinkedHashSet<>();
        private final Map<String, Set<Integer>> effects = new LinkedHashMap<>();
        private final Set<String> guards = new LinkedHashSet<>();

        // 执行 MethodSummary 中的 empty 处理。
        private static MethodSummary empty() { return EMPTY; }
        // 合并 mergeEffect 对应的结果。
        private boolean mergeEffect(String kind, Collection<Integer> parameters) {
            boolean newKind = !effects.containsKey(kind);
            Set<Integer> merged = new LinkedHashSet<>(effects.getOrDefault(kind, Set.of()));
            boolean changed = merged.addAll(parameters);
            effects.put(kind, Set.copyOf(merged));
            return newKind || changed;
        }
        // 判断是否满足 hasEffect 对应的条件。
        private boolean hasEffect(String kind) { return effects.containsKey(kind); }
        // 执行 MethodSummary 中的 taintedEffect 处理。
        private boolean taintedEffect(String kind, Set<Integer> tainted) {
            Set<Integer> affected = effects.get(kind);
            return affected != null && (affected.isEmpty() || affected.stream().anyMatch(tainted::contains));
        }
    }

    // 封装 GraphEdge 使用的不可变结构化数据。
    private record GraphEdge(SemanticCallEdge persisted, MethodModel caller, ProgramNode target,
                             Map<Integer, Set<Integer>> argumentDependencies) {}
    // 封装 PathState 使用的不可变结构化数据。
    private record PathState(ProgramNode current, Set<Integer> taintedParameters,
                             List<ProgramNode> nodes, List<GraphEdge> edges) {}
    // 封装 SecurityPolicy 使用的不可变结构化数据。
    private record SecurityPolicy(String pattern, String action) {}
    // 封装 SecurityFlowCandidate 使用的不可变结构化数据。
    private record SecurityFlowCandidate(SecurityFlow flow, int pathLength) {}
}
